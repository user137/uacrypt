//! Strumok stream cipher (DSTU 8845:2019), 256- and 512-bit key variants.
//!
//! Ported from `docs/pseudocode/strumok.md` (itself transcribed from the designers' paper,
//! `docs/papers/Strumok.pdf` Sections 2-9) and structurally cross-checked against
//! `oracles/strumok-dstu8845/strumok.c` (outspace, unofficial, no license) and
//! `oracles/uapki/library/uapkic/src/dstu8845.c` (UAPKI, BSD-2-Clause, state-expertise pedigree -
//! see `ORACLES.md`). Citation and verification status: `DECISIONS.md` D-18.
//!
//! The `T` nonlinear substitution (Section 7) is exactly one Kalyna/Kupyna round's `eta` (S-box)
//! composed with `tau` (the MDS linear layer) applied to a single 64-bit word treated as an
//! 8-byte column - confirmed by computing it via `hazmat::tables::{SBOXES, MDS_MATRIX,
//! apply_matrix}` and diffing all 2048 entries (8 byte-positions x 256 values) byte-for-byte
//! against both oracles' precomputed `T0..T7` tables (script-verified, not eyeballed). This means
//! `T` needs no dedicated lookup tables of its own, unlike `mul_alpha`/`mul_alpha_inv` below.
//!
//! `MUL_ALPHA`/`MUL_ALPHA_INV` (Sections 8-9, multiplication by the LFSR feedback polynomial's
//! generator in GF(2^64)) are **not** derivable from the Kalyna/Kupyna tables - they belong to a
//! different field construction specific to Strumok's LFSR. Transcribed here from
//! `oracles/uapki/.../dstu8845.c`'s `mul_T`/`invmul_T` (cross-checked byte-identical against
//! `oracles/strumok-dstu8845/strumok.c`'s `strumok_alpha_mul`/`strumok_alphainv_mul` - same
//! lineage per `DECISIONS.md` D-15, so this confirms transcription accuracy, not independence).
//!
//! The state-transition function (`Next`, Section 4) is implemented here as a literal 16-word
//! shift register, per the pseudocode doc's `Next(S_i, mode)` description - not the
//! ring-buffer/in-place rotation both oracles use for throughput. The pseudocode doc already
//! confirms the two are equivalent; the literal-shift form was chosen for this port because it is
//! mechanically checkable against the spec text without needing to re-derive the rotated indexing.
//!
//! Only raw keystream generation/XOR is provided here - no key/IV management beyond what
//! `Init` (Section 3) requires, no higher-level nonce or AEAD construction (that is
//! `crypto_stream`'s job, see `docs/dstu-crypto-project.md` "Concrete API shape").

use super::tables::{apply_matrix, MDS_MATRIX, ROWS, SBOXES};

/// `alpha` multiplication table, indexed by the byte shifted out of the top of the word.
/// Source: `oracles/uapki/library/uapkic/src/dstu8845.c` `mul_T` (see module doc for the
/// cross-check against `oracles/strumok-dstu8845/strumok.c`'s `strumok_alpha_mul`).
#[rustfmt::skip]
#[allow(clippy::unreadable_literal)] // kept byte-for-byte diffable against the oracle source
const MUL_ALPHA: [u64; 256] = [
    0x0000000000000000, 0xd73f04125e000004, 0xb37e0824bc000008, 0x64410c36e200000c,
    0x7bfc104865000010, 0xacc3145a3b000014, 0xc882186cd9000018, 0x1fbd1c7e8700001c,
    0xf6e52090ca000020, 0x21da248294000024, 0x459b28b476000028, 0x92a42ca62800002c,
    0x8d1930d8af000030, 0x5a2634caf1000034, 0x3e6738fc13000038, 0xe9583cee4d00003c,
    0xf1d7403d89000040, 0x26e8442fd7000044, 0x42a9481935000048, 0x95964c0b6b00004c,
    0x8a2b5075ec000050, 0x5d145467b2000054, 0x3955585150000058, 0xee6a5c430e00005c,
    0x073260ad43000060, 0xd00d64bf1d000064, 0xb44c6889ff000068, 0x63736c9ba100006c,
    0x7cce70e526000070, 0xabf174f778000074, 0xcfb078c19a000078, 0x188f7cd3c400007c,
    0xffb3807a0f000080, 0x288c846851000084, 0x4ccd885eb3000088, 0x9bf28c4ced00008c,
    0x844f90326a000090, 0x5370942034000094, 0x37319816d6000098, 0xe00e9c048800009c,
    0x0956a0eac50000a0, 0xde69a4f89b0000a4, 0xba28a8ce790000a8, 0x6d17acdc270000ac,
    0x72aab0a2a00000b0, 0xa595b4b0fe0000b4, 0xc1d4b8861c0000b8, 0x16ebbc94420000bc,
    0x0e64c047860000c0, 0xd95bc455d80000c4, 0xbd1ac8633a0000c8, 0x6a25cc71640000cc,
    0x7598d00fe30000d0, 0xa2a7d41dbd0000d4, 0xc6e6d82b5f0000d8, 0x11d9dc39010000dc,
    0xf881e0d74c0000e0, 0x2fbee4c5120000e4, 0x4bffe8f3f00000e8, 0x9cc0ece1ae0000ec,
    0x837df09f290000f0, 0x5442f48d770000f4, 0x3003f8bb950000f8, 0xe73cfca9cb0000fc,
    0xe37b1df41e00001d, 0x344419e640000019, 0x500515d0a2000015, 0x873a11c2fc000011,
    0x98870dbc7b00000d, 0x4fb809ae25000009, 0x2bf90598c7000005, 0xfcc6018a99000001,
    0x159e3d64d400003d, 0xc2a139768a000039, 0xa6e0354068000035, 0x71df315236000031,
    0x6e622d2cb100002d, 0xb95d293eef000029, 0xdd1c25080d000025, 0x0a23211a53000021,
    0x12ac5dc99700005d, 0xc59359dbc9000059, 0xa1d255ed2b000055, 0x76ed51ff75000051,
    0x69504d81f200004d, 0xbe6f4993ac000049, 0xda2e45a54e000045, 0x0d1141b710000041,
    0xe4497d595d00007d, 0x3376794b03000079, 0x5737757de1000075, 0x8008716fbf000071,
    0x9fb56d113800006d, 0x488a690366000069, 0x2ccb653584000065, 0xfbf46127da000061,
    0x1cc89d8e1100009d, 0xcbf7999c4f000099, 0xafb695aaad000095, 0x788991b8f3000091,
    0x67348dc67400008d, 0xb00b89d42a000089, 0xd44a85e2c8000085, 0x037581f096000081,
    0xea2dbd1edb0000bd, 0x3d12b90c850000b9, 0x5953b53a670000b5, 0x8e6cb128390000b1,
    0x91d1ad56be0000ad, 0x46eea944e00000a9, 0x22afa572020000a5, 0xf590a1605c0000a1,
    0xed1fddb3980000dd, 0x3a20d9a1c60000d9, 0x5e61d597240000d5, 0x895ed1857a0000d1,
    0x96e3cdfbfd0000cd, 0x41dcc9e9a30000c9, 0x259dc5df410000c5, 0xf2a2c1cd1f0000c1,
    0x1bfafd23520000fd, 0xccc5f9310c0000f9, 0xa884f507ee0000f5, 0x7fbbf115b00000f1,
    0x6006ed6b370000ed, 0xb739e979690000e9, 0xd378e54f8b0000e5, 0x0447e15dd50000e1,
    0xdbf63af53c00003a, 0x0cc93ee76200003e, 0x688832d180000032, 0xbfb736c3de000036,
    0xa00a2abd5900002a, 0x77352eaf0700002e, 0x13742299e5000022, 0xc44b268bbb000026,
    0x2d131a65f600001a, 0xfa2c1e77a800001e, 0x9e6d12414a000012, 0x4952165314000016,
    0x56ef0a2d9300000a, 0x81d00e3fcd00000e, 0xe59102092f000002, 0x32ae061b71000006,
    0x2a217ac8b500007a, 0xfd1e7edaeb00007e, 0x995f72ec09000072, 0x4e6076fe57000076,
    0x51dd6a80d000006a, 0x86e26e928e00006e, 0xe2a362a46c000062, 0x359c66b632000066,
    0xdcc45a587f00005a, 0x0bfb5e4a2100005e, 0x6fba527cc3000052, 0xb885566e9d000056,
    0xa7384a101a00004a, 0x70074e024400004e, 0x14464234a6000042, 0xc3794626f8000046,
    0x2445ba8f330000ba, 0xf37abe9d6d0000be, 0x973bb2ab8f0000b2, 0x4004b6b9d10000b6,
    0x5fb9aac7560000aa, 0x8886aed5080000ae, 0xecc7a2e3ea0000a2, 0x3bf8a6f1b40000a6,
    0xd2a09a1ff900009a, 0x059f9e0da700009e, 0x61de923b45000092, 0xb6e196291b000096,
    0xa95c8a579c00008a, 0x7e638e45c200008e, 0x1a22827320000082, 0xcd1d86617e000086,
    0xd592fab2ba0000fa, 0x02adfea0e40000fe, 0x66ecf296060000f2, 0xb1d3f684580000f6,
    0xae6eeafadf0000ea, 0x7951eee8810000ee, 0x1d10e2de630000e2, 0xca2fe6cc3d0000e6,
    0x2377da22700000da, 0xf448de302e0000de, 0x9009d206cc0000d2, 0x4736d614920000d6,
    0x588bca6a150000ca, 0x8fb4ce784b0000ce, 0xebf5c24ea90000c2, 0x3ccac65cf70000c6,
    0x388d270122000027, 0xefb223137c000023, 0x8bf32f259e00002f, 0x5ccc2b37c000002b,
    0x4371374947000037, 0x944e335b19000033, 0xf00f3f6dfb00003f, 0x27303b7fa500003b,
    0xce680791e8000007, 0x19570383b6000003, 0x7d160fb55400000f, 0xaa290ba70a00000b,
    0xb59417d98d000017, 0x62ab13cbd3000013, 0x06ea1ffd3100001f, 0xd1d51bef6f00001b,
    0xc95a673cab000067, 0x1e65632ef5000063, 0x7a246f181700006f, 0xad1b6b0a4900006b,
    0xb2a67774ce000077, 0x6599736690000073, 0x01d87f507200007f, 0xd6e77b422c00007b,
    0x3fbf47ac61000047, 0xe88043be3f000043, 0x8cc14f88dd00004f, 0x5bfe4b9a8300004b,
    0x444357e404000057, 0x937c53f65a000053, 0xf73d5fc0b800005f, 0x20025bd2e600005b,
    0xc73ea77b2d0000a7, 0x1001a369730000a3, 0x7440af5f910000af, 0xa37fab4dcf0000ab,
    0xbcc2b733480000b7, 0x6bfdb321160000b3, 0x0fbcbf17f40000bf, 0xd883bb05aa0000bb,
    0x31db87ebe7000087, 0xe6e483f9b9000083, 0x82a58fcf5b00008f, 0x559a8bdd0500008b,
    0x4a2797a382000097, 0x9d1893b1dc000093, 0xf9599f873e00009f, 0x2e669b956000009b,
    0x36e9e746a40000e7, 0xe1d6e354fa0000e3, 0x8597ef62180000ef, 0x52a8eb70460000eb,
    0x4d15f70ec10000f7, 0x9a2af31c9f0000f3, 0xfe6bff2a7d0000ff, 0x2954fb38230000fb,
    0xc00cc7d66e0000c7, 0x1733c3c4300000c3, 0x7372cff2d20000cf, 0xa44dcbe08c0000cb,
    0xbbf0d79e0b0000d7, 0x6ccfd38c550000d3, 0x088edfbab70000df, 0xdfb1dba8e90000db,
];

/// `alpha^-1` multiplication table, indexed by the byte shifted out of the bottom of the word.
/// Source: `oracles/uapki/library/uapkic/src/dstu8845.c` `invmul_T` (same cross-check as
/// `MUL_ALPHA` above).
#[rustfmt::skip]
#[allow(clippy::unreadable_literal)] // kept byte-for-byte diffable against the oracle source
const MUL_ALPHA_INV: [u64; 256] = [
    0x0000000000000000, 0x47fcc6018a990000, 0x8ee59102092f0000, 0xc919570383b60000,
    0x01d73f04125e0000, 0x462bf90598c70000, 0x8f32ae061b710000, 0xc8ce680791e80000,
    0x02b37e0824bc0000, 0x454fb809ae250000, 0x8c56ef0a2d930000, 0xcbaa290ba70a0000,
    0x0364410c36e20000, 0x4498870dbc7b0000, 0x8d81d00e3fcd0000, 0xca7d160fb5540000,
    0x047bfc1048650000, 0x43873a11c2fc0000, 0x8a9e6d12414a0000, 0xcd62ab13cbd30000,
    0x05acc3145a3b0000, 0x42500515d0a20000, 0x8b49521653140000, 0xccb59417d98d0000,
    0x06c882186cd90000, 0x41344419e6400000, 0x882d131a65f60000, 0xcfd1d51bef6f0000,
    0x071fbd1c7e870000, 0x40e37b1df41e0000, 0x89fa2c1e77a80000, 0xce06ea1ffd310000,
    0x08f6e52090ca0000, 0x4f0a23211a530000, 0x8613742299e50000, 0xc1efb223137c0000,
    0x0921da2482940000, 0x4edd1c25080d0000, 0x87c44b268bbb0000, 0xc0388d2701220000,
    0x0a459b28b4760000, 0x4db95d293eef0000, 0x84a00a2abd590000, 0xc35ccc2b37c00000,
    0x0b92a42ca6280000, 0x4c6e622d2cb10000, 0x8577352eaf070000, 0xc28bf32f259e0000,
    0x0c8d1930d8af0000, 0x4b71df3152360000, 0x82688832d1800000, 0xc5944e335b190000,
    0x0d5a2634caf10000, 0x4aa6e03540680000, 0x83bfb736c3de0000, 0xc443713749470000,
    0x0e3e6738fc130000, 0x49c2a139768a0000, 0x80dbf63af53c0000, 0xc727303b7fa50000,
    0x0fe9583cee4d0000, 0x48159e3d64d40000, 0x810cc93ee7620000, 0xc6f00f3f6dfb0000,
    0x10f1d7403d890000, 0x570d1141b7100000, 0x9e14464234a60000, 0xd9e88043be3f0000,
    0x1126e8442fd70000, 0x56da2e45a54e0000, 0x9fc3794626f80000, 0xd83fbf47ac610000,
    0x1242a94819350000, 0x55be6f4993ac0000, 0x9ca7384a101a0000, 0xdb5bfe4b9a830000,
    0x1395964c0b6b0000, 0x5469504d81f20000, 0x9d70074e02440000, 0xda8cc14f88dd0000,
    0x148a2b5075ec0000, 0x5376ed51ff750000, 0x9a6fba527cc30000, 0xdd937c53f65a0000,
    0x155d145467b20000, 0x52a1d255ed2b0000, 0x9bb885566e9d0000, 0xdc444357e4040000,
    0x1639555851500000, 0x51c59359dbc90000, 0x98dcc45a587f0000, 0xdf20025bd2e60000,
    0x17ee6a5c430e0000, 0x5012ac5dc9970000, 0x990bfb5e4a210000, 0xdef73d5fc0b80000,
    0x18073260ad430000, 0x5ffbf46127da0000, 0x96e2a362a46c0000, 0xd11e65632ef50000,
    0x19d00d64bf1d0000, 0x5e2ccb6535840000, 0x97359c66b6320000, 0xd0c95a673cab0000,
    0x1ab44c6889ff0000, 0x5d488a6903660000, 0x9451dd6a80d00000, 0xd3ad1b6b0a490000,
    0x1b63736c9ba10000, 0x5c9fb56d11380000, 0x9586e26e928e0000, 0xd27a246f18170000,
    0x1c7cce70e5260000, 0x5b8008716fbf0000, 0x92995f72ec090000, 0xd565997366900000,
    0x1dabf174f7780000, 0x5a5737757de10000, 0x934e6076fe570000, 0xd4b2a67774ce0000,
    0x1ecfb078c19a0000, 0x593376794b030000, 0x902a217ac8b50000, 0xd7d6e77b422c0000,
    0x1f188f7cd3c40000, 0x58e4497d595d0000, 0x91fd1e7edaeb0000, 0xd601d87f50720000,
    0x20ffb3807a0f0000, 0x67037581f0960000, 0xae1a228273200000, 0xe9e6e483f9b90000,
    0x21288c8468510000, 0x66d44a85e2c80000, 0xafcd1d86617e0000, 0xe831db87ebe70000,
    0x224ccd885eb30000, 0x65b00b89d42a0000, 0xaca95c8a579c0000, 0xeb559a8bdd050000,
    0x239bf28c4ced0000, 0x6467348dc6740000, 0xad7e638e45c20000, 0xea82a58fcf5b0000,
    0x24844f90326a0000, 0x63788991b8f30000, 0xaa61de923b450000, 0xed9d1893b1dc0000,
    0x2553709420340000, 0x62afb695aaad0000, 0xabb6e196291b0000, 0xec4a2797a3820000,
    0x2637319816d60000, 0x61cbf7999c4f0000, 0xa8d2a09a1ff90000, 0xef2e669b95600000,
    0x27e00e9c04880000, 0x601cc89d8e110000, 0xa9059f9e0da70000, 0xeef9599f873e0000,
    0x280956a0eac50000, 0x6ff590a1605c0000, 0xa6ecc7a2e3ea0000, 0xe11001a369730000,
    0x29de69a4f89b0000, 0x6e22afa572020000, 0xa73bf8a6f1b40000, 0xe0c73ea77b2d0000,
    0x2aba28a8ce790000, 0x6d46eea944e00000, 0xa45fb9aac7560000, 0xe3a37fab4dcf0000,
    0x2b6d17acdc270000, 0x6c91d1ad56be0000, 0xa58886aed5080000, 0xe27440af5f910000,
    0x2c72aab0a2a00000, 0x6b8e6cb128390000, 0xa2973bb2ab8f0000, 0xe56bfdb321160000,
    0x2da595b4b0fe0000, 0x6a5953b53a670000, 0xa34004b6b9d10000, 0xe4bcc2b733480000,
    0x2ec1d4b8861c0000, 0x693d12b90c850000, 0xa02445ba8f330000, 0xe7d883bb05aa0000,
    0x2f16ebbc94420000, 0x68ea2dbd1edb0000, 0xa1f37abe9d6d0000, 0xe60fbcbf17f40000,
    0x300e64c047860000, 0x77f2a2c1cd1f0000, 0xbeebf5c24ea90000, 0xf91733c3c4300000,
    0x31d95bc455d80000, 0x76259dc5df410000, 0xbf3ccac65cf70000, 0xf8c00cc7d66e0000,
    0x32bd1ac8633a0000, 0x7541dcc9e9a30000, 0xbc588bca6a150000, 0xfba44dcbe08c0000,
    0x336a25cc71640000, 0x7496e3cdfbfd0000, 0xbd8fb4ce784b0000, 0xfa7372cff2d20000,
    0x347598d00fe30000, 0x73895ed1857a0000, 0xba9009d206cc0000, 0xfd6ccfd38c550000,
    0x35a2a7d41dbd0000, 0x725e61d597240000, 0xbb4736d614920000, 0xfcbbf0d79e0b0000,
    0x36c6e6d82b5f0000, 0x713a20d9a1c60000, 0xb82377da22700000, 0xffdfb1dba8e90000,
    0x3711d9dc39010000, 0x70ed1fddb3980000, 0xb9f448de302e0000, 0xfe088edfbab70000,
    0x38f881e0d74c0000, 0x7f0447e15dd50000, 0xb61d10e2de630000, 0xf1e1d6e354fa0000,
    0x392fbee4c5120000, 0x7ed378e54f8b0000, 0xb7ca2fe6cc3d0000, 0xf036e9e746a40000,
    0x3a4bffe8f3f00000, 0x7db739e979690000, 0xb4ae6eeafadf0000, 0xf352a8eb70460000,
    0x3b9cc0ece1ae0000, 0x7c6006ed6b370000, 0xb57951eee8810000, 0xf28597ef62180000,
    0x3c837df09f290000, 0x7b7fbbf115b00000, 0xb266ecf296060000, 0xf59a2af31c9f0000,
    0x3d5442f48d770000, 0x7aa884f507ee0000, 0xb3b1d3f684580000, 0xf44d15f70ec10000,
    0x3e3003f8bb950000, 0x79ccc5f9310c0000, 0xb0d592fab2ba0000, 0xf72954fb38230000,
    0x3fe73cfca9cb0000, 0x781bfafd23520000, 0xb102adfea0e40000, 0xf6fe6bff2a7d0000,
];

/// `mul_alpha(w) = (w << 8) xor MUL_ALPHA[top byte of w]` (`docs/pseudocode/strumok.md` Sections
/// 8-9).
fn mul_alpha(w: u64) -> u64 {
    (w << 8) ^ MUL_ALPHA[(w >> 56) as usize]
}

/// `mul_alpha_inv(w) = (w >> 8) xor MUL_ALPHA_INV[bottom byte of w]`.
fn mul_alpha_inv(w: u64) -> u64 {
    (w >> 8) ^ MUL_ALPHA_INV[(w & 0xff) as usize]
}

/// `T(w)`: substitute each of the word's 8 bytes through `S_(j mod 4)`, then apply the shared
/// Kalyna/Kupyna MDS linear layer to the result (see module doc for the byte-for-byte
/// cross-check against both oracles' precomputed tables).
fn t_function(w: u64) -> u64 {
    let mut column = [0u8; ROWS];
    for (j, byte) in column.iter_mut().enumerate() {
        *byte = SBOXES[j % 4][((w >> (8 * j)) & 0xff) as usize];
    }
    let mut state = [column];
    apply_matrix(&mut state, &MDS_MATRIX);
    u64::from_le_bytes(state[0])
}

/// `FSM(x, y, z) = (x +64 y) xor z` (`docs/pseudocode/strumok.md` Section 6).
fn fsm(x: u64, y: u64, z: u64) -> u64 {
    x.wrapping_add(y) ^ z
}

fn word_le(bytes: &[u8], index: usize) -> u64 {
    let start = index * 8;
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[start..start + 8]);
    u64::from_le_bytes(word)
}

/// `Init(K, IV)` (`docs/pseudocode/strumok.md` Section 3): the fixed key/IV-to-word mapping
/// differs by key size, transcribed directly from `oracles/uapki/.../dstu8845.c`
/// `dstu8845_set_iv` per the pseudocode doc's own note that this table should come from a
/// verified source rather than a paraphrase.
fn init_state(key: &[u8], iv: &[u8; 32]) -> [u64; 16] {
    let ivw = |i: usize| word_le(iv, i);
    let kw = |i: usize| word_le(key, i);
    let mut s = [0u64; 16];
    if key.len() == 32 {
        s[0] = kw(3) ^ ivw(0);
        s[1] = kw(2);
        s[2] = kw(1) ^ ivw(1);
        s[3] = kw(0) ^ ivw(2);
        s[4] = kw(3);
        s[5] = kw(2) ^ ivw(3);
        s[6] = !kw(1);
        s[7] = !kw(0);
        s[8] = kw(3);
        s[9] = kw(2);
        s[10] = !kw(1);
        s[11] = kw(0);
        s[12] = kw(3);
        s[13] = !kw(2);
        s[14] = kw(1);
        s[15] = !kw(0);
    } else {
        s[0] = kw(7) ^ ivw(0);
        s[1] = kw(6);
        s[2] = kw(5);
        s[3] = kw(4) ^ ivw(1);
        s[4] = kw(3);
        s[5] = kw(2) ^ ivw(2);
        s[6] = kw(1);
        s[7] = !kw(0);
        s[8] = kw(4) ^ ivw(3);
        s[9] = !kw(6);
        s[10] = kw(5);
        s[11] = !kw(7);
        s[12] = kw(3);
        s[13] = kw(2);
        s[14] = !kw(1);
        s[15] = kw(0);
    }
    s
}

/// `Next(S_i, mode)` (`docs/pseudocode/strumok.md` Section 4), implemented as a literal 16-word
/// shift (see module doc for why this form was chosen over the oracles' rotating-buffer
/// optimization).
fn next_step(s: &mut [u64; 16], r0: &mut u64, r1: &mut u64, init_mode: bool) {
    let (s0, s11, s13, s15) = (s[0], s[11], s[13], s[15]);

    let new_r1 = t_function(*r0);
    let new_r0 = r1.wrapping_add(s13);

    let mut feedback = mul_alpha(s0) ^ mul_alpha_inv(s11) ^ s13;
    if init_mode {
        feedback ^= fsm(s15, *r0, *r1);
    }

    s.copy_within(1..16, 0);
    s[15] = feedback;
    *r0 = new_r0;
    *r1 = new_r1;
}

/// `Strm(S_i) -> Z_i` (`docs/pseudocode/strumok.md` Section 5).
fn strm(s: &[u64; 16], r0: u64, r1: u64) -> u64 {
    fsm(s[15], r0, r1) ^ s[0]
}

/// Shared state machine for both key sizes - only `init_state`'s key-length branch differs.
struct Core {
    s: [u64; 16],
    r0: u64,
    r1: u64,
    block: [u8; 8],
    block_pos: usize,
}

impl Core {
    fn new(key: &[u8], iv: &[u8; 32]) -> Self {
        let mut s = init_state(key, iv);
        let (mut r0, mut r1) = (0u64, 0u64);
        for _ in 0..32 {
            next_step(&mut s, &mut r0, &mut r1, true);
        }
        next_step(&mut s, &mut r0, &mut r1, false);
        Self {
            s,
            r0,
            r1,
            block: [0u8; 8],
            block_pos: 8,
        }
    }

    /// XORs the keystream into `data` in place (applying it to an all-zero buffer yields the raw
    /// keystream, matching `crates/dstu-core/tests/vectors/strumok/keystream-{256,512}.json`).
    fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.block_pos == 8 {
                let z = strm(&self.s, self.r0, self.r1);
                self.block = z.to_le_bytes();
                next_step(&mut self.s, &mut self.r0, &mut self.r1, false);
                self.block_pos = 0;
            }
            *byte ^= self.block[self.block_pos];
            self.block_pos += 1;
        }
    }
}

macro_rules! strumok_variant {
    ($name:ident, $key_bytes:literal) => {
        #[doc = concat!(stringify!($key_bytes), "-byte key, 32-byte IV.")]
        pub struct $name(Core);

        impl $name {
            /// Initializes the cipher state from a key and IV (`Init`).
            #[must_use]
            pub fn new(key: &[u8; $key_bytes], iv: &[u8; 32]) -> Self {
                Self(Core::new(key, iv))
            }

            /// XORs the keystream into `data` in place.
            pub fn apply_keystream(&mut self, data: &mut [u8]) {
                self.0.apply_keystream(data);
            }
        }
    };
}

strumok_variant!(Strumok256, 32);
strumok_variant!(Strumok512, 64);
