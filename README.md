# ButterKnife

ButterKnife is a Zig implementation of a Tweakable Pseudorandom Function (TPRF) based on the masked Iterate-Fork-Iterate design paradigm described in ["Masked Iterate-Fork-Iterate: A new Design Paradigm for Tweakable Expanding Pseudorandom Function"](https://eprint.iacr.org/2022/1534.pdf).

### Key Features:

- Input: 128-bit block
- Tweak: 128-bit tweak value
- Key: 128-bit secret key
- Output: 1024-bit (8 × 128-bit blocks)
- Structure: 7 rounds before branching, 8 rounds per branch, 8 parallel branches
- Based on Deoxys-BC tweakey schedule with AES round functions

## Security Properties

- Pseudorandom function behavior: outputs appear random to any observer without knowledge of the key
- Tweakability: different tweak values produce independent outputs for the same key/message pair
- Expansion: a 128-bit input is expanded to 1024 bits of output
