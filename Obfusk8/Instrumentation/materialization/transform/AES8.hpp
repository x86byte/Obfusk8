#pragma once

#include "K8_UTILS/k8_utils.hpp"

using namespace std;

NOOPT

constexpr uint32_t _obf_date_hash() {
    const char* s = __DATE__;
    uint32_t h = 0x811C9DC5;
    while (*s) { h = (h ^ (uint8_t)*s) * 0x01000193; ++s; }
    s = __TIME__;
    while (*s) { h = (h ^ (uint8_t)*s) * 0x01000193; ++s; }
    return h;
}

        #pragma region AES_CONSTEXPR
            namespace aes_constexpr {
                constexpr uint8_t sbox[256] = {
                        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
                };

                constexpr uint8_t rsbox[256] = {
                    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
                };

                constexpr uint8_t rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

                constexpr void KeyExpansion(const uint8_t* key, uint8_t* w) {
                    for (int i = 0; i < 4; i++) {
                        w[4 * i] = key[4 * i];
                        w[4 * i + 1] = key[4 * i + 1];
                        w[4 * i + 2] = key[4 * i + 2];
                        w[4 * i + 3] = key[4 * i + 3];
                    }
                    for (int i = 4; i < 44; i++) {
                        uint8_t temp[4] = { 0 };
                        temp[0] = w[4 * (i - 1)];
                        temp[1] = w[4 * (i - 1) + 1];
                        temp[2] = w[4 * (i - 1) + 2];
                        temp[3] = w[4 * (i - 1) + 3];

                        if (i % 4 == 0) {
                            uint8_t t = temp[0];
                            temp[0] = sbox[temp[1]] ^ rcon[i / 4];
                            temp[1] = sbox[temp[2]];
                            temp[2] = sbox[temp[3]];
                            temp[3] = sbox[t];
                        }
                        w[4 * i] = w[4 * (i - 4)] ^ temp[0];
                        w[4 * i + 1] = w[4 * (i - 4) + 1] ^ temp[1];
                        w[4 * i + 2] = w[4 * (i - 4) + 2] ^ temp[2];
                        w[4 * i + 3] = w[4 * (i - 4) + 3] ^ temp[3];
                    }
                }

                constexpr void AddRoundKey(uint8_t* state, const uint8_t* roundKey) {
                    for (int i = 0; i < 16; i++) state[i] ^= roundKey[i];
                }

                constexpr void SubBytes(uint8_t* state) {
                    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
                }

                constexpr void InvSubBytes(uint8_t* state) {
                    for (int i = 0; i < 16; i++) state[i] = rsbox[state[i]];
                }

                constexpr void ShiftRows(uint8_t* state) {
                    uint8_t temp[16] = { 0 };
                    for (int i = 0; i < 16; i++) temp[i] = state[i];
                    state[1] = temp[5]; state[5] = temp[9]; state[9] = temp[13]; state[13] = temp[1];
                    state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
                    state[3] = temp[15]; state[7] = temp[3]; state[11] = temp[7]; state[15] = temp[11];
                }

                constexpr void InvShiftRows(uint8_t* state) {
                    uint8_t temp[16] = { 0 };
                    for (int i = 0; i < 16; i++) temp[i] = state[i];
                    state[1] = temp[13]; state[5] = temp[1]; state[9] = temp[5]; state[13] = temp[9];
                    state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
                    state[3] = temp[7]; state[7] = temp[11]; state[11] = temp[15]; state[15] = temp[3];
                }

                constexpr uint8_t gmul(uint8_t a, uint8_t b) {
                    uint8_t p = 0;
                    for (int i = 0; i < 8; i++) {
                        if ((b & 1) != 0) p ^= a;
                        bool hi_bit_set = (a & 0x80) != 0;
                        a <<= 1;
                        if (hi_bit_set) a ^= 0x1B;
                        b >>= 1;
                    }
                    return p;
                }

                constexpr void MixColumns(uint8_t* state) {
                    uint8_t tmp[16] = { 0 };
                    for (int i = 0; i < 16; i++) tmp[i] = state[i];
                    for (int i = 0; i < 4; i++) {
                        state[4 * i] = gmul(tmp[4 * i], 2) ^ gmul(tmp[4 * i + 1], 3) ^ tmp[4 * i + 2] ^ tmp[4 * i + 3];
                        state[4 * i + 1] = tmp[4 * i] ^ gmul(tmp[4 * i + 1], 2) ^ gmul(tmp[4 * i + 2], 3) ^ tmp[4 * i + 3];
                        state[4 * i + 2] = tmp[4 * i] ^ tmp[4 * i + 1] ^ gmul(tmp[4 * i + 2], 2) ^ gmul(tmp[4 * i + 3], 3);
                        state[4 * i + 3] = gmul(tmp[4 * i], 3) ^ tmp[4 * i + 1] ^ tmp[4 * i + 2] ^ gmul(tmp[4 * i + 3], 2);
                    }
                }

                constexpr void InvMixColumns(uint8_t* state) {
                    uint8_t tmp[16] = { 0 };
                    for (int i = 0; i < 16; i++) tmp[i] = state[i];
                    for (int i = 0; i < 4; i++) {
                        state[4 * i] = gmul(tmp[4 * i], 0x0e) ^ gmul(tmp[4 * i + 1], 0x0b) ^ gmul(tmp[4 * i + 2], 0x0d) ^ gmul(tmp[4 * i + 3], 0x09);
                        state[4 * i + 1] = gmul(tmp[4 * i], 0x09) ^ gmul(tmp[4 * i + 1], 0x0e) ^ gmul(tmp[4 * i + 2], 0x0b) ^ gmul(tmp[4 * i + 3], 0x0d);
                        state[4 * i + 2] = gmul(tmp[4 * i], 0x0d) ^ gmul(tmp[4 * i + 1], 0x09) ^ gmul(tmp[4 * i + 2], 0x0e) ^ gmul(tmp[4 * i + 3], 0x0b);
                        state[4 * i + 3] = gmul(tmp[4 * i], 0x0b) ^ gmul(tmp[4 * i + 1], 0x0d) ^ gmul(tmp[4 * i + 2], 0x09) ^ gmul(tmp[4 * i + 3], 0x0e);
                    }
                }

                constexpr void EncryptBlock(uint8_t* in, const uint8_t* key) {
                    uint8_t state[16] = { 0 };
                    uint8_t w[176] = { 0 };
                    for (int i = 0; i < 16; i++) state[i] = in[i];
                    KeyExpansion(key, w);
                    AddRoundKey(state, w);
                    for (int round = 1; round < 10; round++) {
                        SubBytes(state);
                        ShiftRows(state);
                        MixColumns(state);
                        AddRoundKey(state, w + round * 16);
                    }
                    SubBytes(state);
                    ShiftRows(state);
                    AddRoundKey(state, w + 160);
                    for (int i = 0; i < 16; i++) in[i] = state[i];
                }

                constexpr void DecryptBlock(uint8_t* in, const uint8_t* key) {
                    uint8_t state[16] = { 0 };
                    uint8_t w[176] = { 0 };
                    for (int i = 0; i < 16; i++) state[i] = in[i];
                    KeyExpansion(key, w);
                    AddRoundKey(state, w + 160);
                    for (int round = 9; round > 0; round--) {
                        InvShiftRows(state);
                        InvSubBytes(state);
                        AddRoundKey(state, w + round * 16);
                        InvMixColumns(state);
                    }
                    InvShiftRows(state);
                    InvSubBytes(state);
                    AddRoundKey(state, w);
                    for (int i = 0; i < 16; i++) in[i] = state[i];
                }
            }
        #pragma endregion AES_CONSTEXPR

        #pragma region Helpers
            #define AES_KEY_MIX(str, line) ((sizeof(str) ^ ((line) * 0x314159)) ^ 0x271828)
            #define AES_K0(str, line) ((uint8_t)(AES_KEY_MIX(str, line) & 0xFF))
            #define AES_K1(str, line) ((uint8_t)((AES_KEY_MIX(str, line) >> 8)  & 0xFF))
            #define AES_K2(str, line) ((uint8_t)((AES_KEY_MIX(str, line) >> 16) & 0xFF))
            #define AES_K3(str, line) ((uint8_t)((AES_KEY_MIX(str, line) >> 24) & 0xFF))

            #define AES_KEY_MIX_W(str, line) ((sizeof(str) ^ ((line) * 0x618033)) ^ 0x1618033)
            #define AES_KW0(str, line) ((uint8_t)(AES_KEY_MIX_W(str, line) & 0xFF))
            #define AES_KW1(str, line) ((uint8_t)((AES_KEY_MIX_W(str, line) >> 8)  & 0xFF))
            #define AES_KW2(str, line) ((uint8_t)((AES_KEY_MIX_W(str, line) >> 16) & 0xFF))
            #define AES_KW3(str, line) ((uint8_t)((AES_KEY_MIX_W(str, line) >> 24) & 0xFF))

            template <size_t N, uint8_t K0, uint8_t K1, uint8_t K2, uint8_t K3>
            struct _AESObfStrs {
                static constexpr uint8_t key[16] = {
                    K0, K1, K2, K3, K3, K2, K1, K0,
                    K0, K0, K1, K1, K2, K2, K3, K3
                };

                static constexpr array<uint32_t, ((N + 15) / 16 * 4)> encrypt(const char(&plain)[N]) {
                    constexpr size_t num_blocks = (N + 15) / 16;
                    array<uint32_t, num_blocks * 4> enc{};
                    for (size_t b = 0; b < num_blocks; ++b) {
                        uint8_t block[16] = { 0 };
                        for (size_t i = 0; i < 16; ++i) {
                            size_t src_idx = b * 16 + i;
                            if (src_idx < N) block[i] = (uint8_t)plain[src_idx];
                        }
                        aes_constexpr::EncryptBlock(block, key);
                        for (int i = 0; i < 4; ++i)
                            enc[b * 4 + i] = (uint32_t)block[i * 4 + 0]
                                           | ((uint32_t)block[i * 4 + 1] << 8)
                                           | ((uint32_t)block[i * 4 + 2] << 16)
                                           | ((uint32_t)block[i * 4 + 3] << 24);
                    }
                    return enc;
                }
            };

            template <size_t N, uint8_t K0, uint8_t K1, uint8_t K2, uint8_t K3>
            struct _AESObfWStrs {
                static constexpr uint8_t key[16] = {
                    K0, K1, K2, K3, K3, K2, K1, K0,
                    K0, K0, K1, K1, K2, K2, K3, K3
                };

                static constexpr size_t BYTE_N     = N * 2;
                static constexpr size_t NUM_BLOCKS  = (BYTE_N + 15) / 16;

                static constexpr array<uint32_t, NUM_BLOCKS * 4> encrypt(const wchar_t(&plain)[N]) {
                    array<uint32_t, NUM_BLOCKS * 4> enc{};
                    for (size_t b = 0; b < NUM_BLOCKS; ++b) {
                        uint8_t block[16] = {};
                        for (size_t i = 0; i < 16; ++i) {
                            size_t byte_idx = b * 16 + i;
                            if (byte_idx < BYTE_N) {
                                size_t wc  = byte_idx / 2;
                                size_t bic = byte_idx % 2;
                                block[i] = (uint8_t)((plain[wc] >> (bic * 8)) & 0xFF);
                            }
                        }
                        aes_constexpr::EncryptBlock(block, key);
                        for (int i = 0; i < 4; ++i)
                            enc[b * 4 + i] = (uint32_t)block[i * 4 + 0]
                                           | ((uint32_t)block[i * 4 + 1] << 8)
                                           | ((uint32_t)block[i * 4 + 2] << 16)
                                           | ((uint32_t)block[i * 4 + 3] << 24);
                    }
                    return enc;
                }
            };

            #define _L_SUB(a, b) ( \
                ((unsigned int)(a) ^ (unsigned int)(b)) - \
                (2 * ((~(unsigned int)(a)) & (unsigned int)(b))) \
            )

            #define _L_XOR(a, b) ( \
                ((unsigned int)(a) | (unsigned int)(b)) - \
                ((unsigned int)(a) & (unsigned int)(b)) \
            )

            #define _L_OR(a, b) ( \
                ((unsigned int)(a) + (unsigned int)(b)) - \
                ((unsigned int)(a) & (unsigned int)(b)) \
            )

            K8_FORCEINLINE uint32_t _bstrap_hash(const char* str) {
                uint32_t h = _BSTRAP_IV;
                if (!str) return 0;
                while (*str) {
                    char c = *str++;
                    if (c >= 'a' && c <= 'z')
                        c = (char)_L_SUB((int)c, 0x20);
                    uint8_t low_byte = (uint8_t)_L_XOR((h & 0xFF), (uint32_t)c);
                    uint8_t sub = aes_constexpr::sbox[low_byte];
                    h = _L_OR((h >> 8), (h << 24));
                    h = _L_XOR(h, (uint32_t)sub);
                }
                return h;
            }

            K8_FORCEINLINE uint32_t _char_hasher(char c) {
                uint32_t h = _BSTRAP_IV;
                if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')
                   c = (char)_L_SUB((int)c, 0x20);
                uint8_t low_byte = (uint8_t)_L_XOR((h & 0xFF), (uint32_t)c);
                uint8_t sub = aes_constexpr::sbox[low_byte];
                h = _L_OR((h >> 8), (h << 24));
                h = _L_XOR(h, (uint32_t)sub);
                return h;
            }
        #pragma endregion Helpers

        #pragma region Sections
            #define PACKER_SECTION_0 ".reloc"
            #define PACKER_SECTION_1 ".reloc"
            #define PACKER_SECTION_2 ".bss"
            #define PACKER_SECTION_3 ".bss"
            #define PACKER_SECTION_4 ".reloc"
            #define PACKER_SECTION_5 ".reloc"
            #define PACKER_SECTION_6 ".tls"
            #define PACKER_SECTION_7 ".tls"
            #define PACKER_SECTION_8 ".CRT"
            #define PACKER_SECTION_9 ".CRT"
            #define PACKER_SECTION_10 ".idata"
            #define PACKER_SECTION_11 ".idata"
            #define PACKER_SECTION_12 ".edata"
            #define PACKER_SECTION_13 ".edata"
            #define PACKER_SECTION_14 ".00cfg"
            #define PACKER_SECTION_15 ".00cfg"
            #define PACKER_SECTION_16 ".sxdata"
            #define PACKER_SECTION_17 ".sxdata"
            #define PACKER_SECTION_18 ".gfids"
            #define PACKER_SECTION_19 ".gfids"
            #define PACKER_SECTION_20 ".giats"
            #define PACKER_SECTION_21 ".giats"
            #define PACKER_SECTION_22 ".eh_frame"
            #define PACKER_SECTION_23 ".eh_frame"
            #define PACKER_SECTION_24 ".giats"
            #define PACKER_SECTION_25 ".giats"
            #define PACKER_SECTION_26 ".giats"
            #define PACKER_SECTION_27 ".giats"
            #define PACKER_SECTION_28 ".reloc"
            #define PACKER_SECTION_29 ".reloc"
            #define PACKER_SECTION_30 ".bss"
            #define PACKER_SECTION_31 ".bss"
            #define PACKER_SECTION_32 ".reloc"
            #define PACKER_SECTION_33 ".reloc"
            #define PACKER_SECTION_34 ".tls"
            #define PACKER_SECTION_35 ".tls"
            #define PACKER_SECTION_36 ".CRT"
            #define PACKER_SECTION_37 ".CRT"
            #define PACKER_SECTION_38 ".idata"
            #define PACKER_SECTION_39 ".idata"

            #define PICK_SECTION(idx) PACKER_SECTION_##idx

            #if defined(_MSC_VER) || defined(__clang__)
                #pragma section(".reloc", read, write)
                #pragma section(".bss", read, write)
                #pragma section(".tls", read, write)
                #pragma section(".CRT", read, write)
                #pragma section(".idata", read, write)
                #pragma section(".edata", read, write)
                #pragma section(".00cfg", read, write)
                #pragma section(".sxdata", read, write)
                #pragma section(".gfids", read, write)
                #pragma section(".eh_frame", read, write)
                #pragma section(".giats", read, write)
            #endif

            #if defined(_MSC_VER) || defined(__clang__)
                #define DECLARE_SECTION(secname) __pragma(section(secname, read, write))
                #define SECTION_ATTR_SEC(secname) __declspec(allocate(secname))
            #else
                #define DECLARE_SECTION(secname)
                #define SECTION_ATTR_SEC(secname) 
            #endif

            #define SIG_BASE_UPX     0x21585055
            #define SIG_BASE_VMP     0x504d565b
            #define SIG_BASE_ENIGMA  0x47494e45
            #define SIG_BASE_THEMIDA 0x4944454d
            #define SIG_BASE_FSG     0x21475346
            #define SIG_BASE_ASPACK  0x4b434150
            #define SIG_BASE_NSPACK  0x4b43414e
            #define SIG_BASE_MPRESS  0x53534552

            #define GEN_SIG(base, line) (uint32_t)((base) ^ ((line) * 0x78654) ^ 0x874275372)
        #pragma endregion Sections

        template <typename T, size_t N, uint8_t K0, uint8_t K1, uint8_t K2, uint8_t K3>
        constexpr auto _obf_get_encrypted(const T(&str)[N]) {
            if constexpr (sizeof(T) > 1)
                return _AESObfWStrs<N, K0, K1, K2, K3>::encrypt(str);
            else
                return _AESObfStrs<N, K0, K1, K2, K3>::encrypt(str);
        }

        #define CONCAT2(a,b) a##b
        #define CONCAT(a,b) CONCAT2(a,b)

        #define _INTERNAL_OBF(str) \
                ([]() { \
                    struct _OD { \
                        using _CharT = remove_cv_t<remove_reference_t<decltype(str[0])>>; \
                        static constexpr size_t _RAW_SIZE() { return sizeof(str); } \
                        static constexpr size_t _NUM_CHUNKS() { return (_RAW_SIZE() + 15) / 16; } \
                        static constexpr size_t _N_CHARS() { return _RAW_SIZE() / sizeof(_CharT); } \
                        static constexpr uint32_t _BUILD_HASH() { return _obf_date_hash(); } \
                        static constexpr uint32_t _DATE_MIX() { return _BUILD_HASH() ^ (__LINE__ * 0x9E3779B9u); } \
                        static constexpr uint8_t _k0() { return (sizeof(_CharT) > 1 ? AES_KW0(str, __LINE__) : AES_K0(str, __LINE__)) ^ ((uint8_t)(_DATE_MIX() & 0xFF)); } \
                        static constexpr uint8_t _k1() { return (sizeof(_CharT) > 1 ? AES_KW1(str, __LINE__) : AES_K1(str, __LINE__)) ^ ((uint8_t)((_DATE_MIX() >> 8) & 0xFF)); } \
                        static constexpr uint8_t _k2() { return (sizeof(_CharT) > 1 ? AES_KW2(str, __LINE__) : AES_K2(str, __LINE__)) ^ ((uint8_t)((_DATE_MIX() >> 16) & 0xFF)); } \
                        static constexpr uint8_t _k3() { return (sizeof(_CharT) > 1 ? AES_KW3(str, __LINE__) : AES_K3(str, __LINE__)) ^ ((uint8_t)((_DATE_MIX() >> 24) & 0xFF)); } \
                        static constexpr auto _enc() { return _obf_get_encrypted<_CharT, _N_CHARS(), _k0(), _k1(), _k2(), _k3()>(str); } \
                    }; \
                    static_assert(_OD::_NUM_CHUNKS() <= 40, "[Obfusk8] String exceeds 640-byte limit."); \
                    uint32_t _ks[4] = { _OD::_k0(), _OD::_k1(), _OD::_k2(), _OD::_k3() }; \
                    uint8_t runtime_key[16]; \
                    uint32_t _kx = _OD::_BUILD_HASH(); \
                    for (int _i = 0; _i < 16; ++_i) { \
                        int _m = (_i < 4) ? _i : (_i < 8) ? (7 - _i) : (_i < 12) ? ((_i - 8) >> 1) : (((_i - 12) >> 1) + 2); \
                        _kx = _L_XOR(_kx, _ks[_m]); \
                        _kx = _L_SUB(_kx, (uint32_t)_i); \
                        runtime_key[_i] = (uint8_t)(_ks[_m] ^ (_kx & 0xFF)); \
                        _kx ^= (uint32_t)runtime_key[_i]; \
                    } \
                    _kx = _OD::_BUILD_HASH(); \
                    for (int _i = 0; _i < 16; ++_i) { \
                        int _m = (_i < 4) ? _i : (_i < 8) ? (7 - _i) : (_i < 12) ? ((_i - 8) >> 1) : (((_i - 12) >> 1) + 2); \
                        _kx = _L_XOR(_kx, _ks[_m]); \
                        _kx = _L_SUB(_kx, (uint32_t)_i); \
                        runtime_key[_i] ^= (uint8_t)(_kx & 0xFF); \
                        _kx ^= (uint32_t)(_ks[_m] ^ (_kx & 0xFF)); \
                    } \
                    { \
                        uint32_t _op = _L_XOR(_OD::_BUILD_HASH(), _OD::_BUILD_HASH()); \
                        if (_L_SUB(_op, 1) == 0xFFFFFFFFu) { \
                            _ks[0] ^= _ks[1]; _ks[1] ^= _ks[0]; _ks[0] ^= _ks[1]; \
                        } \
                    } \
                    return _obf_decrypt_and_clear<typename _OD::_CharT>( \
                        _OD::_enc().data(), _OD::_NUM_CHUNKS(), _OD::_RAW_SIZE(), \
                        runtime_key, _ks); \
                })()

        #define OBFUSCATE_STRING(str) _INTERNAL_OBF(str)
        #define OBFUSCATE_WSTRING(str) _INTERNAL_OBF(str)

        #pragma region SHARED_RUNTIME_DECRYPT
            NOOPT
            template<typename _CharT>
            static conditional_t<(sizeof(_CharT) > 1), wstring, string>
            _obf_decrypt_and_clear(const uint32_t* enc_data, size_t num_chunks, size_t raw_size,
                                   uint8_t* runtime_key, uint32_t* _ks) {
                uint8_t out_raw[640];
                for (size_t chunk = 0; chunk < num_chunks; ++chunk) {
                    uint8_t block[16];
                    for (int i = 0; i < 4; ++i) {
                        uint32_t val = enc_data[chunk * 4 + i];
                        block[i*4+0] = (uint8_t)(val & 0xFF);
                        block[i*4+1] = (uint8_t)((val >> 8) & 0xFF);
                        block[i*4+2] = (uint8_t)((val >> 16) & 0xFF);
                        block[i*4+3] = (uint8_t)((val >> 24) & 0xFF);
                    }
                    aes_constexpr::DecryptBlock(block, runtime_key);
                    for (size_t j = 0; j < 16; ++j)
                        out_raw[chunk * 16 + j] = block[j];
                }
                using result_t = conditional_t<(sizeof(_CharT) > 1), wstring, string>;
                result_t result;
                if constexpr (sizeof(_CharT) > 1) {
                    size_t wlen = raw_size / sizeof(wchar_t);
                    if (wlen > 0) --wlen;
                    result.resize(wlen);
                    for (size_t i = 0; i < wlen; ++i)
                        result[i] = (wchar_t)((uint16_t)out_raw[i*2] | ((uint16_t)out_raw[i*2+1] << 8));
                } else {
                    size_t final_len = raw_size;
                    for (size_t i = 0; i < final_len; ++i)
                        if (out_raw[i] == 0) { final_len = i; break; }
                    result = string((char*)out_raw, final_len);
                }
                memset(runtime_key, 0, 16);
                memset(out_raw, 0, sizeof(out_raw));
                memset(_ks, 0, 16);
                return result;
            }
            OPT
        #pragma endregion SHARED_RUNTIME_DECRYPT
OPT
