const std = @import("std");
const ButterKnife = @import("butterknife").ButterKnife;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("ButterKnife TPRF Implementation\n", .{});
    try stdout.print("=================================\n\n", .{});

    // Example 1: All-zero inputs
    try stdout.print("Example 1: All-zero inputs\n", .{});
    {
        const message: [16]u8 = @splat(0);
        const tweak: [16]u8 = @splat(0);
        const key: [16]u8 = @splat(0);
        var output: [128]u8 = undefined;

        ButterKnife.eval(message, tweak, key, &output);

        try stdout.print("Message: ", .{});
        try printHex(stdout, &message);
        try stdout.print("Tweak:   ", .{});
        try printHex(stdout, &tweak);
        try stdout.print("Key:     ", .{});
        try printHex(stdout, &key);
        try stdout.print("\nOutput (8 branches × 128 bits):\n", .{});

        for (0..8) |i| {
            try stdout.print("  Branch {}: ", .{i});
            try printHex(stdout, output[i * 16 .. (i + 1) * 16]);
        }
        try stdout.print("\n", .{});
    }

    // Example 2: Simple test vector
    try stdout.print("Example 2: Simple test vector\n", .{});
    {
        var message: [16]u8 = @splat(0);
        message[0] = 0x01;
        message[1] = 0x23;
        message[2] = 0x45;
        message[3] = 0x67;

        var tweak: [16]u8 = @splat(0);
        tweak[0] = 0x89;
        tweak[1] = 0xab;
        tweak[2] = 0xcd;
        tweak[3] = 0xef;

        var key: [16]u8 = @splat(0);
        key[0] = 0xfe;
        key[1] = 0xdc;
        key[2] = 0xba;
        key[3] = 0x98;

        var output: [128]u8 = undefined;

        ButterKnife.eval(message, tweak, key, &output);

        try stdout.print("Message: ", .{});
        try printHex(stdout, &message);
        try stdout.print("Tweak:   ", .{});
        try printHex(stdout, &tweak);
        try stdout.print("Key:     ", .{});
        try printHex(stdout, &key);
        try stdout.print("\nOutput (8 branches × 128 bits):\n", .{});

        for (0..8) |i| {
            try stdout.print("  Branch {}: ", .{i});
            try printHex(stdout, output[i * 16 .. (i + 1) * 16]);
        }
        try stdout.print("\n", .{});
    }

    // Demonstrate avalanche effect
    try stdout.print("Example 3: Avalanche effect (1-bit difference in message)\n", .{});
    {
        var message1: [16]u8 = @splat(0);
        var message2: [16]u8 = @splat(0);
        message2[0] = 0x01; // Single bit changed

        const tweak: [16]u8 = @splat(0);
        const key: [16]u8 = @splat(0);

        var output1: [128]u8 = undefined;
        var output2: [128]u8 = undefined;

        ButterKnife.eval(message1, tweak, key, &output1);
        ButterKnife.eval(message2, tweak, key, &output2);

        try stdout.print("Message 1: ", .{});
        try printHex(stdout, &message1);
        try stdout.print("Message 2: ", .{});
        try printHex(stdout, &message2);
        try stdout.print("\nHamming distance per branch:\n", .{});

        for (0..8) |i| {
            const branch1 = output1[i * 16 .. (i + 1) * 16];
            const branch2 = output2[i * 16 .. (i + 1) * 16];
            const distance = hammingDistance(branch1, branch2);
            try stdout.print("  Branch {}: {} bits (out of 128)\n", .{ i, distance });
        }
        try stdout.print("\n", .{});
    }

    try stdout.flush();
}

fn printHex(writer: anytype, bytes: []const u8) !void {
    for (bytes) |byte| {
        try writer.print("{x:0>2}", .{byte});
    }
    try writer.print("\n", .{});
}

fn hammingDistance(a: []const u8, b: []const u8) usize {
    var distance: usize = 0;
    for (a, b) |byte_a, byte_b| {
        var xor_val = byte_a ^ byte_b;
        while (xor_val != 0) : (xor_val >>= 1) {
            distance += xor_val & 1;
        }
    }
    return distance;
}
