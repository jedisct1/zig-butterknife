const std = @import("std");
const aes = std.crypto.core.aes;

/// ButterKnife: A Tweakable Pseudorandom Function based on masked Iterate-Fork-Iterate
/// Specification from "Masked Iterate-Fork-Iterate: A new Design Paradigm for
/// Tweakable Expanding Pseudorandom Function" (2021)
///
/// - Input: 128-bit block
/// - Tweak: 128-bit tweak
/// - Key: 128-bit key (256-bit tweakey = tweak || key)
/// - Output: 1024-bit (8 × 128-bit blocks)
/// - Structure: 7 rounds before branching, 8 rounds per branch, 8 parallel branches
/// Deoxys round constants
const RCON = [17]u8{
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72,
};

/// Deoxys permutation table
const PERM = [16]usize{ 1, 6, 11, 12, 5, 10, 15, 0, 9, 14, 3, 4, 13, 2, 7, 8 };

/// Add branch constant to round key (XOR into column 2)
fn prepareRoundKey(round_tweakey: aes.Block, branch: u8) aes.Block {
    var key_bytes = round_tweakey.toBytes();
    // XOR branch constant into column 2 (bytes 8-11 in column-major layout)
    inline for (0..4) |row| {
        key_bytes[8 + row] ^= branch;
    }
    return aes.Block.fromBytes(&key_bytes);
}

/// Apply Deoxys LFSR (G function with alpha=2)
fn applyLFSR2(tweakey: *[16]u8) void {
    inline for (tweakey) |*byte| {
        byte.* = (byte.* << 1) | (((byte.* & 0x20) >> 5) ^ ((byte.* & 0x80) >> 7));
    }
}

/// Apply Deoxys permutation (H function)
fn applyPermutation(tweakey: *[16]u8) void {
    var tmp: [16]u8 = undefined;
    inline for (0..16) |i| {
        tmp[PERM[i]] = tweakey[i];
    }
    tweakey.* = tmp;
}

/// Tweakey schedule for Deoxys-BC
const TweakeySchedule = struct {
    round_tweakeys: [16]aes.Block,

    pub fn init(tk1_bytes: [16]u8, tk2_bytes: [16]u8) TweakeySchedule {
        var schedule: TweakeySchedule = undefined;
        var tk1 = tk1_bytes;
        var tk2 = tk2_bytes;

        const rcon_row0: u32 = 0x01020408; // Fixed constant for row 0

        for (0..16) |round| {
            // Build round tweakey in column-major format (4 columns × 4 rows)
            var round_key_bytes: [16]u8 = undefined;

            // Column 0: XOR with fixed constant 0x01020408
            inline for (0..4) |row| {
                const const_byte: u8 = @truncate(rcon_row0 >> @intCast((3 - row) * 8));
                round_key_bytes[row] = tk1[row] ^ tk2[row] ^ const_byte;
            }

            // Column 1: XOR with RCON[round]
            inline for (0..4) |row| {
                round_key_bytes[4 + row] = tk1[4 + row] ^ tk2[4 + row] ^ RCON[round];
            }

            // Columns 2 and 3: Just XOR TK1 and TK2
            inline for (0..4) |row| {
                round_key_bytes[8 + row] = tk1[8 + row] ^ tk2[8 + row];
                round_key_bytes[12 + row] = tk1[12 + row] ^ tk2[12 + row];
            }

            // Store as aes.Block directly
            schedule.round_tweakeys[round] = aes.Block.fromBytes(&round_key_bytes);

            // Apply H permutation to both TK1 and TK2
            applyPermutation(&tk1);
            applyPermutation(&tk2);

            // Apply G function with alpha=2 to TK1 (LFSR)
            applyLFSR2(&tk1);
        }

        return schedule;
    }
};

/// ButterKnife context
pub const ButterKnife = struct {
    const BRANCHES = 8;
    const ROUNDS_BEFORE_FORK = 7;
    const ROUNDS_PER_BRANCH = 8;

    /// Evaluate ButterKnife TPRF
    /// Input: 128-bit message, 128-bit tweak, 128-bit key
    /// Output: 1024-bit output (8 × 128-bit blocks)
    pub fn eval(
        message: [16]u8,
        tweak: [16]u8,
        key: [16]u8,
        output: *[128]u8, // 8 blocks × 16 bytes
    ) void {
        // Convert message to AES Block
        var block = aes.Block.fromBytes(&message);

        // Generate tweakey schedule (same for all branches)
        const schedule = TweakeySchedule.init(tweak, key);

        // Execute rounds before forking (7 rounds)
        // Apply first round key
        block = aes.Block.fromBytes(&block.xorBytes(&schedule.round_tweakeys[0].toBytes()));

        // Rounds 1-6
        for (1..ROUNDS_BEFORE_FORK) |round| {
            block = block.encrypt(schedule.round_tweakeys[round]);
        }

        // Final SB+SR+MC (encrypt with zero key since ARK(0) is no-op)
        const zero_key = aes.Block.fromBytes(&@splat(0));
        block = block.encrypt(zero_key);

        // Save fork block for masking outputs
        const fork_block = block;

        // Initialize all branch blocks (all start from the same fork state)
        var branch_blocks: [BRANCHES]aes.Block = @splat(block);

        // Apply first round key to all branches
        for (0..BRANCHES) |i| {
            const round_key = prepareRoundKey(schedule.round_tweakeys[ROUNDS_BEFORE_FORK], @intCast(i + 1));
            branch_blocks[i] = aes.Block.fromBytes(&branch_blocks[i].xorBytes(&round_key.toBytes()));
        }

        // Process rounds 1-7 across all branches
        for (1..ROUNDS_PER_BRANCH) |round| {
            const round_idx = ROUNDS_BEFORE_FORK + round;
            var round_keys: [BRANCHES]aes.Block = undefined;
            for (0..BRANCHES) |i| {
                round_keys[i] = prepareRoundKey(schedule.round_tweakeys[round_idx], @intCast(i + 1));
            }
            branch_blocks = aes.Block.parallel.encryptParallel(BRANCHES, branch_blocks, round_keys);
        }

        // Final SB+SR+MC for all branches
        const zero_keys: [BRANCHES]aes.Block = @splat(zero_key);
        branch_blocks = aes.Block.parallel.encryptParallel(BRANCHES, branch_blocks, zero_keys);

        // Final tweakey addition and feed-forward with fork state (mIFI masking)
        const fork_bytes = fork_block.toBytes();
        for (0..BRANCHES) |i| {
            const final_key = prepareRoundKey(schedule.round_tweakeys[ROUNDS_BEFORE_FORK + ROUNDS_PER_BRANCH], @intCast(i + 1));
            const branch_bytes = branch_blocks[i].xorBytes(&final_key.toBytes());
            const offset = i * 16;
            inline for (0..16) |j| {
                output[offset + j] = branch_bytes[j] ^ fork_bytes[j];
            }
        }
    }
};

test "ButterKnife basic operation" {
    const message: [16]u8 = @splat(0);
    const tweak: [16]u8 = @splat(0);
    const key: [16]u8 = @splat(0);
    var output: [128]u8 = undefined;

    ButterKnife.eval(message, tweak, key, &output);

    // Output should be non-zero and different across branches
    var all_zero = true;
    for (output) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "ButterKnife different inputs produce different outputs" {
    var output1: [128]u8 = undefined;
    var output2: [128]u8 = undefined;

    const message1: [16]u8 = @splat(0);
    var message2: [16]u8 = @splat(0);
    message2[0] = 1; // Changed one bit

    const tweak: [16]u8 = @splat(0);
    const key: [16]u8 = @splat(0);

    ButterKnife.eval(message1, tweak, key, &output1);
    ButterKnife.eval(message2, tweak, key, &output2);

    // Outputs should be different
    try std.testing.expect(!std.mem.eql(u8, &output1, &output2));
}

test "ButterKnife test vectors - all zero inputs" {
    const message: [16]u8 = @splat(0);
    const tweak: [16]u8 = @splat(0);
    const key: [16]u8 = @splat(0);
    var output: [128]u8 = undefined;

    ButterKnife.eval(message, tweak, key, &output);

    const expected_branch0 = [_]u8{ 0x39, 0xb7, 0xa3, 0x70, 0xf5, 0xef, 0xd7, 0x68, 0x7f, 0xfb, 0xe3, 0xfc, 0x95, 0x05, 0x78, 0x23 };
    const expected_branch1 = [_]u8{ 0xcb, 0x01, 0x2e, 0x68, 0x76, 0xd8, 0x85, 0x51, 0x30, 0xf5, 0x6f, 0xdb, 0x08, 0x46, 0x8c, 0x3e };
    const expected_branch2 = [_]u8{ 0x5d, 0x7f, 0x5d, 0xad, 0x0c, 0xd0, 0x03, 0x12, 0x63, 0x37, 0xaf, 0xff, 0x3b, 0x72, 0x77, 0x3f };
    const expected_branch3 = [_]u8{ 0xdd, 0x31, 0xa9, 0x6d, 0xd0, 0xda, 0x79, 0x53, 0xf5, 0x9e, 0xe3, 0xfb, 0xeb, 0x2d, 0x0e, 0x40 };
    const expected_branch4 = [_]u8{ 0xd4, 0xf5, 0xa3, 0x40, 0x91, 0x57, 0x73, 0xc9, 0x33, 0xb0, 0xa9, 0x6d, 0x79, 0xbf, 0x2a, 0xef };
    const expected_branch5 = [_]u8{ 0x6c, 0x8b, 0x54, 0x9b, 0xb0, 0x67, 0x6d, 0x7e, 0xc2, 0x61, 0xe3, 0x4b, 0xa0, 0x47, 0x03, 0xd7 };
    const expected_branch6 = [_]u8{ 0xff, 0x1f, 0x32, 0xa5, 0xe2, 0xf8, 0x51, 0x53, 0xc3, 0xce, 0x9b, 0x67, 0x1c, 0x96, 0x00, 0x1f };
    const expected_branch7 = [_]u8{ 0x00, 0x1c, 0x41, 0x5a, 0xac, 0x99, 0xee, 0x26, 0xce, 0xcc, 0xd3, 0xe3, 0xf0, 0x0d, 0xe2, 0x8c };

    try std.testing.expectEqualSlices(u8, &expected_branch0, output[0..16]);
    try std.testing.expectEqualSlices(u8, &expected_branch1, output[16..32]);
    try std.testing.expectEqualSlices(u8, &expected_branch2, output[32..48]);
    try std.testing.expectEqualSlices(u8, &expected_branch3, output[48..64]);
    try std.testing.expectEqualSlices(u8, &expected_branch4, output[64..80]);
    try std.testing.expectEqualSlices(u8, &expected_branch5, output[80..96]);
    try std.testing.expectEqualSlices(u8, &expected_branch6, output[96..112]);
    try std.testing.expectEqualSlices(u8, &expected_branch7, output[112..128]);
}
