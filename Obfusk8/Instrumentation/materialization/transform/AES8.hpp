#pragma once

#include "K8_UTILS/k8_utils.hpp"

using namespace std;

NOOPT
        #pragma region AES_CONSTEXPR
        // ------------------------------------------------
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
        // ------------------------------------------------
        #pragma endregion AES_CONSTEXPR

        #pragma region Helpers
        // ------------------------------------------------
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

            template<size_t IDX, size_t N>
            constexpr uint32_t _obf_safe_enc(const array<uint32_t, N>& arr) noexcept {
                if constexpr (IDX < N)
                    return arr[IDX];
                else
                    return static_cast<uint32_t>(0xC0DE0000U | ((IDX ^ (N * 0x37)) & 0xFFFFU));
            }

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

            #define CONCAT2(a,b) a##b
            #define CONCAT(a,b) CONCAT2(a,b)
        // ------------------------------------------------
        #pragma endregion Helpers

        #pragma region Chunks
        // ------------------------------------------------
            #pragma region MSVC_CLANG-CL_sections
            // ------------------------------------------------
                    #define PACKER_SECTION_0 ".themida"
                    #define PACKER_SECTION_1 ".vmp1"
                    #define PACKER_SECTION_2 ".enigma2"
                    #define PACKER_SECTION_3 ".vmp0"
                    #define PACKER_SECTION_4 ".FSG!"
                    #define PACKER_SECTION_5 ".aspack"
                    #define PACKER_SECTION_6 ".nsp1"
                    #define PACKER_SECTION_7 ".vmp2"
                    #define PACKER_SECTION_8 ".UPX0"
                    #define PACKER_SECTION_9 ".\npdata"
                    #define PACKER_SECTION_10 ".UPX2"
                    #define PACKER_SECTION_11 ".vmp3"
                    #define PACKER_SECTION_12 ".pec1"
                    #define PACKER_SECTION_13 ".pec2"
                    #define PACKER_SECTION_14 ".petite"
                    #define PACKER_SECTION_15 ".mpress1"
                    #define PACKER_SECTION_16 ".mpress2"
                    #define PACKER_SECTION_17 ".xtls"
                    #define PACKER_SECTION_18 ".arch"
                    #define PACKER_SECTION_19 ".mrdata"
                    #define PACKER_SECTION_20 ".dsstext"
                    #define PACKER_SECTION_21 ".vmp4"
                    #define PACKER_SECTION_22 ".vmp5"
                    #define PACKER_SECTION_23 ".vmp6"
                    #define PACKER_SECTION_24 ".vmp7"
                    #define PACKER_SECTION_25 ".vmp8"
                    #define PACKER_SECTION_26 ".enigma1"
                    #define PACKER_SECTION_27 ".nsp0"
                    #define PACKER_SECTION_28 ".aspack2"
                    #define PACKER_SECTION_29 ".upx3"
                    #define PACKER_SECTION_30 ".vmp9"
                    #define PACKER_SECTION_31 ".enigma3"
                    #define PACKER_SECTION_32 ".themida2"
                    #define PACKER_SECTION_33 ".fsg2"
                    #define PACKER_SECTION_34 ".nsp2"
                    #define PACKER_SECTION_35 ".pec3"
                    #define PACKER_SECTION_36 ".petite2"
                    #define PACKER_SECTION_37 ".mpress3"
                    #define PACKER_SECTION_38 ".tls2"
                    #define PACKER_SECTION_39 ".pdata2"

                    #define PICK_SECTION(idx) PACKER_SECTION_##idx

                    #if defined(_MSC_VER) || defined(__clang__)
                        #pragma section(".enigma2", read, write)
                        #pragma section(".vmp0", read, write)
                        #pragma section(".FSG!", read, write)
                        #pragma section(".aspack", read, write)
                        #pragma section(".nsp1", read, write)
                        #pragma section(".vmp2", read, write)
                        #pragma section(".UPX0", read, write)
                        #pragma section(".pdata", read, write)
                        #pragma section(".UPX2", read, write)
                        #pragma section(".vmp3", read, write)
                        #pragma section(".pec1", read, write)
                        #pragma section(".pec2", read, write)
                        #pragma section(".petite", read, write)
                        #pragma section(".mpress1", read, write)
                        #pragma section(".mpress2", read, write)
                        #pragma section(".xtls", read, write)
                        #pragma section(".arch", read, write)
                        #pragma section(".mrdata", read, write)
                        #pragma section(".dsstext", read, write)
                        #pragma section(".vmp4", read, write)
                        #pragma section(".vmp5", read, write)
                        #pragma section(".vmp6", read, write)
                        #pragma section(".vmp7", read, write)
                        #pragma section(".vmp8", read, write)
                        #pragma section(".enigma1", read, write)
                        #pragma section(".nsp0", read, write)
                        #pragma section(".aspack2", read, write)
                        #pragma section(".upx3", read, write)
                        #pragma section(".vmp9", read, write)
                        #pragma section(".enigma3", read, write)
                        #pragma section(".themida2", read, write)
                        #pragma section(".fsg2", read, write)
                        #pragma section(".nsp2", read, write)
                        #pragma section(".pec3", read, write)
                        #pragma section(".petite2", read, write)
                        #pragma section(".mpress3", read, write)
                        #pragma section(".tls2", read, write)
                        #pragma section(".pdata2", read, write)
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
        // ------------------------------------------------
        #pragma endregion MSVC_CLANG-CL_sections

        template <typename T, size_t N, uint8_t K0, uint8_t K1, uint8_t K2, uint8_t K3>
                constexpr auto _obf_get_encrypted(const T(&str)[N]) {
                        if constexpr (sizeof(T) > 1)
                                return _AESObfWStrs<N, K0, K1, K2, K3>::encrypt(str);
                        else
                                return _AESObfStrs<N, K0, K1, K2, K3>::encrypt(str);
        }

        template <typename T, size_t N, uint8_t K0, uint8_t K1, uint8_t K2, uint8_t K3>
                constexpr const uint8_t* _obf_get_key() {
                        if constexpr (sizeof(T) > 1)
                                return _AESObfWStrs<N, K0, K1, K2, K3>::key;
                        else
                                return _AESObfStrs<N, K0, K1, K2, K3>::key;
        }

        #define _INTERNAL_OBF(str) \
                ([]() { \
                        using _CharT = remove_cv_t<remove_reference_t<decltype(str[0])>>; \
                        constexpr size_t _RAW_SIZE = sizeof(str); \
                        constexpr size_t _NUM_CHUNKS = (_RAW_SIZE + 15) / 16; \
                        static_assert(_NUM_CHUNKS <= 40, "[Obfusk8] String exceeds 640-byte limit."); \
                        constexpr uint8_t _k0 = sizeof(_CharT) > 1 ? AES_KW0(str, __LINE__) : AES_K0(str, __LINE__); \
                        constexpr uint8_t _k1 = sizeof(_CharT) > 1 ? AES_KW1(str, __LINE__) : AES_K1(str, __LINE__); \
                        constexpr uint8_t _k2 = sizeof(_CharT) > 1 ? AES_KW2(str, __LINE__) : AES_K2(str, __LINE__); \
                        constexpr uint8_t _k3 = sizeof(_CharT) > 1 ? AES_KW3(str, __LINE__) : AES_K3(str, __LINE__); \
                        constexpr auto encrypted = _obf_get_encrypted<_CharT, _RAW_SIZE / sizeof(_CharT), _k0, _k1, _k2, _k3>(str); \
                        DECLARE_SECTION(PICK_SECTION(0)) static SECTION_ATTR_SEC(PICK_SECTION(0)) uint32_t CONCAT(_c0_, __LINE__)[5] = { GEN_SIG(SIG_BASE_UPX, __LINE__), _obf_safe_enc<0>(encrypted), _obf_safe_enc<1>(encrypted), _obf_safe_enc<2>(encrypted), _obf_safe_enc<3>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(1)) static SECTION_ATTR_SEC(PICK_SECTION(1)) uint32_t CONCAT(_c1_, __LINE__)[5] = { GEN_SIG(SIG_BASE_VMP, __LINE__), _obf_safe_enc<4>(encrypted), _obf_safe_enc<5>(encrypted), _obf_safe_enc<6>(encrypted), _obf_safe_enc<7>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(2)) static SECTION_ATTR_SEC(PICK_SECTION(2)) uint32_t CONCAT(_c2_, __LINE__)[5] = { GEN_SIG(SIG_BASE_ENIGMA, __LINE__), _obf_safe_enc<8>(encrypted), _obf_safe_enc<9>(encrypted), _obf_safe_enc<10>(encrypted), _obf_safe_enc<11>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(3)) static SECTION_ATTR_SEC(PICK_SECTION(3)) uint32_t CONCAT(_c3_, __LINE__)[5] = { GEN_SIG(SIG_BASE_THEMIDA, __LINE__), _obf_safe_enc<12>(encrypted), _obf_safe_enc<13>(encrypted), _obf_safe_enc<14>(encrypted), _obf_safe_enc<15>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(4)) static SECTION_ATTR_SEC(PICK_SECTION(4)) uint32_t CONCAT(_c4_, __LINE__)[5] = { GEN_SIG(SIG_BASE_FSG, __LINE__), _obf_safe_enc<16>(encrypted), _obf_safe_enc<17>(encrypted), _obf_safe_enc<18>(encrypted), _obf_safe_enc<19>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(5)) static SECTION_ATTR_SEC(PICK_SECTION(5)) uint32_t CONCAT(_c5_, __LINE__)[5] = { GEN_SIG(SIG_BASE_ASPACK, __LINE__), _obf_safe_enc<20>(encrypted), _obf_safe_enc<21>(encrypted), _obf_safe_enc<22>(encrypted), _obf_safe_enc<23>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(6)) static SECTION_ATTR_SEC(PICK_SECTION(6)) uint32_t CONCAT(_c6_, __LINE__)[5] = { GEN_SIG(SIG_BASE_NSPACK, __LINE__), _obf_safe_enc<24>(encrypted), _obf_safe_enc<25>(encrypted), _obf_safe_enc<26>(encrypted), _obf_safe_enc<27>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(7)) static SECTION_ATTR_SEC(PICK_SECTION(7)) uint32_t CONCAT(_c7_, __LINE__)[5] = { GEN_SIG(SIG_BASE_MPRESS, __LINE__), _obf_safe_enc<28>(encrypted), _obf_safe_enc<29>(encrypted), _obf_safe_enc<30>(encrypted), _obf_safe_enc<31>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(8)) static SECTION_ATTR_SEC(PICK_SECTION(8)) uint32_t CONCAT(_c8_, __LINE__)[5] = { GEN_SIG(SIG_BASE_UPX, __LINE__+1), _obf_safe_enc<32>(encrypted), _obf_safe_enc<33>(encrypted), _obf_safe_enc<34>(encrypted), _obf_safe_enc<35>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(9)) static SECTION_ATTR_SEC(PICK_SECTION(9)) uint32_t CONCAT(_c9_, __LINE__)[5] = { GEN_SIG(SIG_BASE_VMP, __LINE__+1), _obf_safe_enc<36>(encrypted), _obf_safe_enc<37>(encrypted), _obf_safe_enc<38>(encrypted), _obf_safe_enc<39>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(10)) static SECTION_ATTR_SEC(PICK_SECTION(10)) uint32_t CONCAT(_c10_, __LINE__)[5] = { GEN_SIG(SIG_BASE_ENIGMA, __LINE__+1), _obf_safe_enc<40>(encrypted), _obf_safe_enc<41>(encrypted), _obf_safe_enc<42>(encrypted), _obf_safe_enc<43>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(11)) static SECTION_ATTR_SEC(PICK_SECTION(11)) uint32_t CONCAT(_c11_, __LINE__)[5] = { GEN_SIG(SIG_BASE_THEMIDA, __LINE__+1), _obf_safe_enc<44>(encrypted), _obf_safe_enc<45>(encrypted), _obf_safe_enc<46>(encrypted), _obf_safe_enc<47>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(12)) static SECTION_ATTR_SEC(PICK_SECTION(12)) uint32_t CONCAT(_c12_, __LINE__)[5] = { GEN_SIG(SIG_BASE_FSG, __LINE__+1), _obf_safe_enc<48>(encrypted), _obf_safe_enc<49>(encrypted), _obf_safe_enc<50>(encrypted), _obf_safe_enc<51>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(13)) static SECTION_ATTR_SEC(PICK_SECTION(13)) uint32_t CONCAT(_c13_, __LINE__)[5] = { GEN_SIG(SIG_BASE_ASPACK, __LINE__+1), _obf_safe_enc<52>(encrypted), _obf_safe_enc<53>(encrypted), _obf_safe_enc<54>(encrypted), _obf_safe_enc<55>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(14)) static SECTION_ATTR_SEC(PICK_SECTION(14)) uint32_t CONCAT(_c14_, __LINE__)[5] = { GEN_SIG(SIG_BASE_NSPACK, __LINE__+1), _obf_safe_enc<56>(encrypted), _obf_safe_enc<57>(encrypted), _obf_safe_enc<58>(encrypted), _obf_safe_enc<59>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(15)) static SECTION_ATTR_SEC(PICK_SECTION(15)) uint32_t CONCAT(_c15_, __LINE__)[5] = { GEN_SIG(SIG_BASE_MPRESS, __LINE__+1), _obf_safe_enc<60>(encrypted), _obf_safe_enc<61>(encrypted), _obf_safe_enc<62>(encrypted), _obf_safe_enc<63>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(16)) static SECTION_ATTR_SEC(PICK_SECTION(16)) uint32_t CONCAT(_c16_, __LINE__)[5] = { GEN_SIG(SIG_BASE_UPX, __LINE__+2), _obf_safe_enc<64>(encrypted), _obf_safe_enc<65>(encrypted), _obf_safe_enc<66>(encrypted), _obf_safe_enc<67>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(17)) static SECTION_ATTR_SEC(PICK_SECTION(17)) uint32_t CONCAT(_c17_, __LINE__)[5] = { GEN_SIG(SIG_BASE_VMP, __LINE__+2), _obf_safe_enc<68>(encrypted), _obf_safe_enc<69>(encrypted), _obf_safe_enc<70>(encrypted), _obf_safe_enc<71>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(18)) static SECTION_ATTR_SEC(PICK_SECTION(18)) uint32_t CONCAT(_c18_, __LINE__)[5] = { GEN_SIG(SIG_BASE_ENIGMA, __LINE__+2), _obf_safe_enc<72>(encrypted), _obf_safe_enc<73>(encrypted), _obf_safe_enc<74>(encrypted), _obf_safe_enc<75>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(19)) static SECTION_ATTR_SEC(PICK_SECTION(19)) uint32_t CONCAT(_c19_, __LINE__)[5] = { GEN_SIG(SIG_BASE_THEMIDA, __LINE__+2), _obf_safe_enc<76>(encrypted), _obf_safe_enc<77>(encrypted), _obf_safe_enc<78>(encrypted), _obf_safe_enc<79>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(20)) static SECTION_ATTR_SEC(PICK_SECTION(20)) uint32_t CONCAT(_c20_, __LINE__)[5] = { GEN_SIG(SIG_BASE_FSG, __LINE__+2), _obf_safe_enc<80>(encrypted), _obf_safe_enc<81>(encrypted), _obf_safe_enc<82>(encrypted), _obf_safe_enc<83>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(21)) static SECTION_ATTR_SEC(PICK_SECTION(21)) uint32_t CONCAT(_c21_, __LINE__)[5] = { GEN_SIG(SIG_BASE_ASPACK, __LINE__+2), _obf_safe_enc<84>(encrypted), _obf_safe_enc<85>(encrypted), _obf_safe_enc<86>(encrypted), _obf_safe_enc<87>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(22)) static SECTION_ATTR_SEC(PICK_SECTION(22)) uint32_t CONCAT(_c22_, __LINE__)[5] = { GEN_SIG(SIG_BASE_NSPACK, __LINE__+2), _obf_safe_enc<88>(encrypted), _obf_safe_enc<89>(encrypted), _obf_safe_enc<90>(encrypted), _obf_safe_enc<91>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(23)) static SECTION_ATTR_SEC(PICK_SECTION(23)) uint32_t CONCAT(_c23_, __LINE__)[5] = { GEN_SIG(SIG_BASE_MPRESS, __LINE__+2), _obf_safe_enc<92>(encrypted), _obf_safe_enc<93>(encrypted), _obf_safe_enc<94>(encrypted), _obf_safe_enc<95>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(24)) static SECTION_ATTR_SEC(PICK_SECTION(24)) uint32_t CONCAT(_c24_, __LINE__)[5] = { GEN_SIG(SIG_BASE_UPX, __LINE__+3), _obf_safe_enc<96>(encrypted), _obf_safe_enc<97>(encrypted), _obf_safe_enc<98>(encrypted), _obf_safe_enc<99>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(25)) static SECTION_ATTR_SEC(PICK_SECTION(25)) uint32_t CONCAT(_c25_, __LINE__)[5] = { GEN_SIG(SIG_BASE_VMP, __LINE__+3), _obf_safe_enc<100>(encrypted), _obf_safe_enc<101>(encrypted), _obf_safe_enc<102>(encrypted), _obf_safe_enc<103>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(26)) static SECTION_ATTR_SEC(PICK_SECTION(26)) uint32_t CONCAT(_c26_, __LINE__)[5] = { GEN_SIG(SIG_BASE_ENIGMA, __LINE__+3), _obf_safe_enc<104>(encrypted), _obf_safe_enc<105>(encrypted), _obf_safe_enc<106>(encrypted), _obf_safe_enc<107>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(27)) static SECTION_ATTR_SEC(PICK_SECTION(27)) uint32_t CONCAT(_c27_, __LINE__)[5] = { GEN_SIG(SIG_BASE_THEMIDA, __LINE__+3), _obf_safe_enc<108>(encrypted), _obf_safe_enc<109>(encrypted), _obf_safe_enc<110>(encrypted), _obf_safe_enc<111>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(28)) static SECTION_ATTR_SEC(PICK_SECTION(28)) uint32_t CONCAT(_c28_, __LINE__)[5] = { GEN_SIG(SIG_BASE_UPX, __LINE__+3), _obf_safe_enc<112>(encrypted), _obf_safe_enc<113>(encrypted), _obf_safe_enc<114>(encrypted), _obf_safe_enc<115>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(29)) static SECTION_ATTR_SEC(PICK_SECTION(29)) uint32_t CONCAT(_c29_, __LINE__)[5] = { GEN_SIG(SIG_BASE_VMP, __LINE__+3), _obf_safe_enc<116>(encrypted), _obf_safe_enc<117>(encrypted), _obf_safe_enc<118>(encrypted), _obf_safe_enc<119>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(30)) static SECTION_ATTR_SEC(PICK_SECTION(30)) uint32_t CONCAT(_c30_, __LINE__)[5] = { GEN_SIG(SIG_BASE_ENIGMA, __LINE__+3), _obf_safe_enc<120>(encrypted), _obf_safe_enc<121>(encrypted), _obf_safe_enc<122>(encrypted), _obf_safe_enc<123>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(31)) static SECTION_ATTR_SEC(PICK_SECTION(31)) uint32_t CONCAT(_c31_, __LINE__)[5] = { GEN_SIG(SIG_BASE_THEMIDA, __LINE__+3), _obf_safe_enc<124>(encrypted), _obf_safe_enc<125>(encrypted), _obf_safe_enc<126>(encrypted), _obf_safe_enc<127>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(32)) static SECTION_ATTR_SEC(PICK_SECTION(32)) uint32_t CONCAT(_c32_, __LINE__)[5] = { GEN_SIG(SIG_BASE_FSG, __LINE__+3), _obf_safe_enc<128>(encrypted), _obf_safe_enc<129>(encrypted), _obf_safe_enc<130>(encrypted), _obf_safe_enc<131>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(33)) static SECTION_ATTR_SEC(PICK_SECTION(33)) uint32_t CONCAT(_c33_, __LINE__)[5] = { GEN_SIG(SIG_BASE_ASPACK, __LINE__+3), _obf_safe_enc<132>(encrypted), _obf_safe_enc<133>(encrypted), _obf_safe_enc<134>(encrypted), _obf_safe_enc<135>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(34)) static SECTION_ATTR_SEC(PICK_SECTION(34)) uint32_t CONCAT(_c34_, __LINE__)[5] = { GEN_SIG(SIG_BASE_NSPACK, __LINE__+3), _obf_safe_enc<136>(encrypted), _obf_safe_enc<137>(encrypted), _obf_safe_enc<138>(encrypted), _obf_safe_enc<139>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(35)) static SECTION_ATTR_SEC(PICK_SECTION(35)) uint32_t CONCAT(_c35_, __LINE__)[5] = { GEN_SIG(SIG_BASE_MPRESS, __LINE__+3), _obf_safe_enc<140>(encrypted), _obf_safe_enc<141>(encrypted), _obf_safe_enc<142>(encrypted), _obf_safe_enc<143>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(36)) static SECTION_ATTR_SEC(PICK_SECTION(36)) uint32_t CONCAT(_c36_, __LINE__)[5] = { GEN_SIG(SIG_BASE_UPX, __LINE__+4), _obf_safe_enc<144>(encrypted), _obf_safe_enc<145>(encrypted), _obf_safe_enc<146>(encrypted), _obf_safe_enc<147>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(37)) static SECTION_ATTR_SEC(PICK_SECTION(37)) uint32_t CONCAT(_c37_, __LINE__)[5] = { GEN_SIG(SIG_BASE_VMP, __LINE__+4), _obf_safe_enc<148>(encrypted), _obf_safe_enc<149>(encrypted), _obf_safe_enc<150>(encrypted), _obf_safe_enc<151>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(38)) static SECTION_ATTR_SEC(PICK_SECTION(38)) uint32_t CONCAT(_c38_, __LINE__)[5] = { GEN_SIG(SIG_BASE_ENIGMA, __LINE__+4), _obf_safe_enc<152>(encrypted), _obf_safe_enc<153>(encrypted), _obf_safe_enc<154>(encrypted), _obf_safe_enc<155>(encrypted) }; \
                        DECLARE_SECTION(PICK_SECTION(39)) static SECTION_ATTR_SEC(PICK_SECTION(39)) uint32_t CONCAT(_c39_, __LINE__)[5] = { GEN_SIG(SIG_BASE_THEMIDA, __LINE__+4), _obf_safe_enc<156>(encrypted), _obf_safe_enc<157>(encrypted), _obf_safe_enc<158>(encrypted), _obf_safe_enc<159>(encrypted) }; \
                        \
                        uint8_t out_raw[40 * 16] = {}; \
                        const uint8_t* key_ptr = _obf_get_key<_CharT, _RAW_SIZE / sizeof(_CharT), _k0, _k1, _k2, _k3>(); \
                        for (int chunk = 0; chunk < (int)_NUM_CHUNKS; ++chunk) { \
                            uint32_t* cp = nullptr; \
                            switch(chunk) { \
                                case 0: cp = CONCAT(_c0_, __LINE__); break; case 1: cp = CONCAT(_c1_, __LINE__); break; \
                                case 2: cp = CONCAT(_c2_, __LINE__); break; case 3: cp = CONCAT(_c3_, __LINE__); break; \
                                case 4: cp = CONCAT(_c4_, __LINE__); break; case 5: cp = CONCAT(_c5_, __LINE__); break; \
                                case 6: cp = CONCAT(_c6_, __LINE__); break; case 7: cp = CONCAT(_c7_, __LINE__); break; \
                                case 8: cp = CONCAT(_c8_, __LINE__); break; case 9: cp = CONCAT(_c9_, __LINE__); break; \
                                case 10: cp = CONCAT(_c10_, __LINE__); break; case 11: cp = CONCAT(_c11_, __LINE__); break; \
                                case 12: cp = CONCAT(_c12_, __LINE__); break; case 13: cp = CONCAT(_c13_, __LINE__); break; \
                                case 14: cp = CONCAT(_c14_, __LINE__); break; case 15: cp = CONCAT(_c15_, __LINE__); break; \
                                case 16: cp = CONCAT(_c16_, __LINE__); break; case 17: cp = CONCAT(_c17_, __LINE__); break; \
                                case 18: cp = CONCAT(_c18_, __LINE__); break; case 19: cp = CONCAT(_c19_, __LINE__); break; \
                                case 20: cp = CONCAT(_c20_, __LINE__); break; case 21: cp = CONCAT(_c21_, __LINE__); break; \
                                case 22: cp = CONCAT(_c22_, __LINE__); break; case 23: cp = CONCAT(_c23_, __LINE__); break; \
                                case 24: cp = CONCAT(_c24_, __LINE__); break; case 25: cp = CONCAT(_c25_, __LINE__); break; \
                                case 26: cp = CONCAT(_c26_, __LINE__); break; case 27: cp = CONCAT(_c27_, __LINE__); break; \
                                case 28: cp = CONCAT(_c28_, __LINE__); break; case 29: cp = CONCAT(_c29_, __LINE__); break; \
                                case 30: cp = CONCAT(_c30_, __LINE__); break; case 31: cp = CONCAT(_c31_, __LINE__); break; \
                                case 32: cp = CONCAT(_c32_, __LINE__); break; case 33: cp = CONCAT(_c33_, __LINE__); break; \
                                case 34: cp = CONCAT(_c34_, __LINE__); break; case 35: cp = CONCAT(_c35_, __LINE__); break; \
                                case 36: cp = CONCAT(_c36_, __LINE__); break; case 37: cp = CONCAT(_c37_, __LINE__); break; \
                                case 38: cp = CONCAT(_c38_, __LINE__); break; case 39: cp = CONCAT(_c39_, __LINE__); break; \
                            } \
                            if (!cp)\
                                break; \
                            uint8_t block[16]; \
                            for(int i = 0; i < 4; ++i) { \
                                block[i*4+0] = (cp[i+1] >> 0) & 0xFF; \
                                block[i*4+1] = (cp[i+1] >> 8) & 0xFF; \
                                block[i*4+2] = (cp[i+1] >> 16) & 0xFF; \
                                block[i*4+3] = (cp[i+1] >> 24) & 0xFF; \
                            } \
                            aes_constexpr::DecryptBlock(block, key_ptr); \
                            for (size_t j = 0; j < 16; ++j) \
                                out_raw[chunk * 16 + j] = block[j]; \
                        } \
                        if constexpr (sizeof(_CharT) > 1) { \
                            wstring ws;\
                            ws.resize((_RAW_SIZE / sizeof(wchar_t)) - 1); \
                            for(size_t i = 0; i < ws.size(); ++i)\
                                ws[i] = (wchar_t)((uint16_t)out_raw[i*2] | ((uint16_t)out_raw[i*2+1] << 8)); \
                            return ws; \
                        } else \
                            return string((char*)out_raw, _RAW_SIZE - 1); \
                    })()

                #define OBFUSCATE_STRING(str) _INTERNAL_OBF(str)
                #define OBFUSCATE_WSTRING(str) _INTERNAL_OBF(str)
        // ------------------------------------------------
        #pragma endregion Chunks
OPT
