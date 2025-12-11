#pragma once

#include <cstdint>
#include <string>
#include <array>
#include <utility>
#include "k8_utils.hpp"

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
                    uint8_t temp[4] = {0};
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
                uint8_t temp[16] = {0};
                for (int i = 0; i < 16; i++) temp[i] = state[i];
                state[1] = temp[5]; state[5] = temp[9]; state[9] = temp[13]; state[13] = temp[1];
                state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
                state[3] = temp[15]; state[7] = temp[3]; state[11] = temp[7]; state[15] = temp[11];
            }
        
            constexpr void InvShiftRows(uint8_t* state) {
                uint8_t temp[16] = {0};
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
                uint8_t tmp[16] = {0};
                for (int i = 0; i < 16; i++) tmp[i] = state[i];
                for (int i = 0; i < 4; i++) {
                    state[4 * i] = gmul(tmp[4 * i], 2) ^ gmul(tmp[4 * i + 1], 3) ^ tmp[4 * i + 2] ^ tmp[4 * i + 3];
                    state[4 * i + 1] = tmp[4 * i] ^ gmul(tmp[4 * i + 1], 2) ^ gmul(tmp[4 * i + 2], 3) ^ tmp[4 * i + 3];
                    state[4 * i + 2] = tmp[4 * i] ^ tmp[4 * i + 1] ^ gmul(tmp[4 * i + 2], 2) ^ gmul(tmp[4 * i + 3], 3);
                    state[4 * i + 3] = gmul(tmp[4 * i], 3) ^ tmp[4 * i + 1] ^ tmp[4 * i + 2] ^ gmul(tmp[4 * i + 3], 2);
                }
            }
        
            constexpr void InvMixColumns(uint8_t* state) {
                uint8_t tmp[16] = {0};
                for (int i = 0; i < 16; i++) tmp[i] = state[i];
                for (int i = 0; i < 4; i++) {
                    state[4 * i] = gmul(tmp[4 * i], 0x0e) ^ gmul(tmp[4 * i + 1], 0x0b) ^ gmul(tmp[4 * i + 2], 0x0d) ^ gmul(tmp[4 * i + 3], 0x09);
                    state[4 * i + 1] = gmul(tmp[4 * i], 0x09) ^ gmul(tmp[4 * i + 1], 0x0e) ^ gmul(tmp[4 * i + 2], 0x0b) ^ gmul(tmp[4 * i + 3], 0x0d);
                    state[4 * i + 2] = gmul(tmp[4 * i], 0x0d) ^ gmul(tmp[4 * i + 1], 0x09) ^ gmul(tmp[4 * i + 2], 0x0e) ^ gmul(tmp[4 * i + 3], 0x0b);
                    state[4 * i + 3] = gmul(tmp[4 * i], 0x0b) ^ gmul(tmp[4 * i + 1], 0x0d) ^ gmul(tmp[4 * i + 2], 0x09) ^ gmul(tmp[4 * i + 3], 0x0e);
                }
            }
        
            constexpr void EncryptBlock(uint8_t* in, const uint8_t* key) {
                uint8_t state[16] = {0};
                uint8_t w[176] = {0};
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
                uint8_t state[16] = {0};
                uint8_t w[176] = {0};
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
        // 128 bit K
        #define AES_KEY_MIX(str, line) ((sizeof(str) ^ ((line) * 0x314159)) ^ 0x271828)
        #define AES_K0(str, line) ((uint8_t)(AES_KEY_MIX(str, line) & 0xFF))
        #define AES_K1(str, line) ((uint8_t)((AES_KEY_MIX(str, line) >> 8) & 0xFF))
        #define AES_K2(str, line) ((uint8_t)((AES_KEY_MIX(str, line) >> 16) & 0xFF))
        #define AES_K3(str, line) ((uint8_t)((AES_KEY_MIX(str, line) >> 24) & 0xFF))
    
        template <size_t N, uint8_t K0, uint8_t K1, uint8_t K2, uint8_t K3>
        struct _AESObfStrs {
            static constexpr uint8_t key[16] = { 
                K0, K1, K2, K3, K3, K2, K1, K0, 
                K0, K0, K1, K1, K2, K2, K3, K3 
            };
    
            static constexpr std::array<uint32_t, ((N + 15) / 16 * 4)> encrypt(const char (&plain)[N]) {
                constexpr size_t num_blocks = (N + 15) / 16;
                std::array<uint32_t, num_blocks * 4> enc{};
    
                for (size_t b = 0; b < num_blocks; ++b) {
                    uint8_t block[16] = {0};
                    for(size_t i=0; i<16; ++i) {
                        size_t src_idx = b*16 + i;
                        if(src_idx < N) block[i] = (uint8_t)plain[src_idx];
                    }
                    aes_constexpr::EncryptBlock(block, key);
                    for(int i=0; i<4; ++i) {
                        enc[b*4 + i] =  (uint32_t)block[i*4 + 0] | 
                                       ((uint32_t)block[i*4 + 1] << 8) | 
                                       ((uint32_t)block[i*4 + 2] << 16) | 
                                       ((uint32_t)block[i*4 + 3] << 24);
                    }
                }
                return enc;
            }
        };
    
        #define CONCAT2(a,b) a##b
        #define CONCAT(a,b) CONCAT2(a,b)
    // ------------------------------------------------
    #pragma endregion Helpers
    
    #pragma region Chunks
    // ------------------------------------------------
            #pragma region MSVC_sections
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
                    
                    #define PICK_SECTION(idx) PACKER_SECTION_##idx
            
                    #if defined(_MSC_VER)
                        // attr Read/Write Standard for data variables
                        #pragma section(".themida", read, write)
                        #pragma section(".vmp1", read, write)
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
                        
                        #define DECLARE_SECTION(secname) __pragma(section(secname, read, write))
                        #define SECTION_ATTR_SEC(secname) __declspec(allocate(secname))
                    #endif
            
                    // Base Entropy
                    #define SIG_BASE_UPX     0x21585055
                    #define SIG_BASE_VMP     0x504d565b
                    #define SIG_BASE_ENIGMA  0x47494e45
                    #define SIG_BASE_THEMIDA 0x4944454d
                    #define SIG_BASE_FSG     0x21475346
                    #define SIG_BASE_ASPACK  0x4b434150
                    #define SIG_BASE_NSPACK  0x4b43414e
                    #define SIG_BASE_MPRESS  0x53534552
            
                    #define GEN_SIG(base, line) (uint32_t)((base) ^ ((line) * 0x1337) ^ 0xDEADBEEF)
            // ------------------------------------------------
            #pragma endregion MSVC_sections
        
            #define OBFUSCATE_STRING(str) \
                ([]() -> std::string { \
                    using _Obf = _AESObfStrs<sizeof(str), \
                        AES_K0(str, __LINE__), AES_K1(str, __LINE__), AES_K2(str, __LINE__), AES_K3(str, __LINE__)>; \
                    constexpr auto encrypted = _Obf::encrypt(str); \
                    DECLARE_SECTION(PICK_SECTION(0)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(0)) uint32_t CONCAT(_obfstr_chunk0_, __LINE__)[5] = { GEN_SIG(SIG_BASE_UPX, __LINE__),      encrypted[0],  encrypted[1], encrypted[2], encrypted[3]  }; \
                    DECLARE_SECTION(PICK_SECTION(1)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(1)) uint32_t CONCAT(_obfstr_chunk1_, __LINE__)[5] = { GEN_SIG(SIG_BASE_THEMIDA, __LINE__),  encrypted[4],  encrypted[5], encrypted[6], encrypted[7]  }; \
                    DECLARE_SECTION(PICK_SECTION(2)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(2)) uint32_t CONCAT(_obfstr_chunk2_, __LINE__)[5] = { GEN_SIG(SIG_BASE_ENIGMA, __LINE__),   encrypted[8],  encrypted[9], encrypted[10], encrypted[11]  }; \
                    DECLARE_SECTION(PICK_SECTION(3)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(3)) uint32_t CONCAT(_obfstr_chunk3_, __LINE__)[5] = { GEN_SIG(SIG_BASE_VMP, __LINE__),      encrypted[12], encrypted[13], encrypted[14], encrypted[15]  }; \
                    DECLARE_SECTION(PICK_SECTION(4)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(4)) uint32_t CONCAT(_obfstr_chunk4_, __LINE__)[5] = { GEN_SIG(SIG_BASE_FSG, __LINE__),      encrypted[16], encrypted[17], encrypted[18], encrypted[19]  }; \
                    DECLARE_SECTION(PICK_SECTION(5)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(5)) uint32_t CONCAT(_obfstr_chunk5_, __LINE__)[5] = { GEN_SIG(SIG_BASE_ASPACK, __LINE__),   encrypted[20], encrypted[21], encrypted[22], encrypted[23] }; \
                    DECLARE_SECTION(PICK_SECTION(6)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(6)) uint32_t CONCAT(_obfstr_chunk6_, __LINE__)[5] = { GEN_SIG(SIG_BASE_NSPACK, __LINE__),   encrypted[24], encrypted[25], encrypted[26], encrypted[27] }; \
                    DECLARE_SECTION(PICK_SECTION(7)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(7)) uint32_t CONCAT(_obfstr_chunk7_, __LINE__)[5] = { GEN_SIG(SIG_BASE_MPRESS, __LINE__),   encrypted[28], encrypted[29], encrypted[30], encrypted[31] }; \
                    DECLARE_SECTION(PICK_SECTION(8)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(8)) uint32_t CONCAT(_obfstr_chunk8_, __LINE__)[5] = { GEN_SIG(SIG_BASE_UPX, __LINE__ + 1),      encrypted[32], encrypted[33], encrypted[34], encrypted[35] }; \
                    DECLARE_SECTION(PICK_SECTION(9)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(9)) uint32_t CONCAT(_obfstr_chunk9_, __LINE__)[5] = { GEN_SIG(SIG_BASE_THEMIDA, __LINE__ + 1),  encrypted[36], encrypted[37], encrypted[38], encrypted[39] }; \
                    DECLARE_SECTION(PICK_SECTION(10)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(10)) uint32_t CONCAT(_obfstr_chunk10_, __LINE__)[5] = { GEN_SIG(SIG_BASE_ENIGMA, __LINE__ + 1),  encrypted[40], encrypted[41], encrypted[42], encrypted[43] }; \
                    DECLARE_SECTION(PICK_SECTION(11)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(11)) uint32_t CONCAT(_obfstr_chunk11_, __LINE__)[5] = { GEN_SIG(SIG_BASE_VMP, __LINE__ + 1),     encrypted[44], encrypted[45], encrypted[46], encrypted[47] }; \
                    DECLARE_SECTION(PICK_SECTION(12)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(12)) uint32_t CONCAT(_obfstr_chunk12_, __LINE__)[5] = { GEN_SIG(SIG_BASE_FSG, __LINE__ + 1),     encrypted[48], encrypted[49], encrypted[50], encrypted[51] }; \
                    DECLARE_SECTION(PICK_SECTION(13)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(13)) uint32_t CONCAT(_obfstr_chunk13_, __LINE__)[5] = { GEN_SIG(SIG_BASE_ASPACK, __LINE__ + 1),  encrypted[52], encrypted[53], encrypted[54], encrypted[55] }; \
                    DECLARE_SECTION(PICK_SECTION(14)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(14)) uint32_t CONCAT(_obfstr_chunk14_, __LINE__)[5] = { GEN_SIG(SIG_BASE_NSPACK, __LINE__ + 1),  encrypted[56], encrypted[57], encrypted[58], encrypted[59] }; \
                    DECLARE_SECTION(PICK_SECTION(15)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(15)) uint32_t CONCAT(_obfstr_chunk15_, __LINE__)[5] = { GEN_SIG(SIG_BASE_MPRESS, __LINE__ + 1),  encrypted[60], encrypted[61], encrypted[62], encrypted[63] }; \
                    DECLARE_SECTION(PICK_SECTION(16)) \
                    static SECTION_ATTR_SEC(PICK_SECTION(16)) uint32_t CONCAT(_obfstr_chunk16_, __LINE__)[5] = { GEN_SIG(SIG_BASE_UPX, __LINE__ + 2),     encrypted[64], encrypted[65], encrypted[66], encrypted[67] }; \
                    char out[((sizeof(str) + 15) / 16) * 16 + 1]; \
                    for (int chunk = 0; chunk < 17; ++chunk) { \
                        uint32_t* chunk_ptr; \
                        uint32_t expected_sig_base; \
                        int line_offset = 0; \
                        switch(chunk) { \
                            case 0: chunk_ptr = CONCAT(_obfstr_chunk0_, __LINE__); expected_sig_base = SIG_BASE_UPX; break; \
                            case 1: chunk_ptr = CONCAT(_obfstr_chunk1_, __LINE__); expected_sig_base = SIG_BASE_THEMIDA; break; \
                            case 2: chunk_ptr = CONCAT(_obfstr_chunk2_, __LINE__); expected_sig_base = SIG_BASE_ENIGMA; break; \
                            case 3: chunk_ptr = CONCAT(_obfstr_chunk3_, __LINE__); expected_sig_base = SIG_BASE_VMP; break; \
                            case 4: chunk_ptr = CONCAT(_obfstr_chunk4_, __LINE__); expected_sig_base = SIG_BASE_FSG; break; \
                            case 5: chunk_ptr = CONCAT(_obfstr_chunk5_, __LINE__); expected_sig_base = SIG_BASE_ASPACK; break; \
                            case 6: chunk_ptr = CONCAT(_obfstr_chunk6_, __LINE__); expected_sig_base = SIG_BASE_NSPACK; break; \
                            case 7: chunk_ptr = CONCAT(_obfstr_chunk7_, __LINE__); expected_sig_base = SIG_BASE_MPRESS; break; \
                            case 8: chunk_ptr = CONCAT(_obfstr_chunk8_, __LINE__); expected_sig_base = SIG_BASE_UPX; line_offset = 1; break; \
                            case 9: chunk_ptr = CONCAT(_obfstr_chunk9_, __LINE__); expected_sig_base = SIG_BASE_THEMIDA; line_offset = 1; break; \
                            case 10: chunk_ptr = CONCAT(_obfstr_chunk10_, __LINE__); expected_sig_base = SIG_BASE_ENIGMA; line_offset = 1; break; \
                            case 11: chunk_ptr = CONCAT(_obfstr_chunk11_, __LINE__); expected_sig_base = SIG_BASE_VMP; line_offset = 1; break; \
                            case 12: chunk_ptr = CONCAT(_obfstr_chunk12_, __LINE__); expected_sig_base = SIG_BASE_FSG; line_offset = 1; break; \
                            case 13: chunk_ptr = CONCAT(_obfstr_chunk13_, __LINE__); expected_sig_base = SIG_BASE_ASPACK; line_offset = 1; break; \
                            case 14: chunk_ptr = CONCAT(_obfstr_chunk14_, __LINE__); expected_sig_base = SIG_BASE_NSPACK; line_offset = 1; break; \
                            case 15: chunk_ptr = CONCAT(_obfstr_chunk15_, __LINE__); expected_sig_base = SIG_BASE_MPRESS; line_offset = 1; break; \
                            case 16: chunk_ptr = CONCAT(_obfstr_chunk16_, __LINE__); expected_sig_base = SIG_BASE_UPX; line_offset = 2; break; \
                            default: chunk_ptr = nullptr; expected_sig_base = 0; \
                        } \
                        if (!chunk_ptr) break; \
                        uint8_t block[16]; \
                        for(int i=0; i<4; ++i) { \
                            block[i*4+0] = (chunk_ptr[i+1] >> 0) & 0xFF; \
                            block[i*4+1] = (chunk_ptr[i+1] >> 8) & 0xFF; \
                            block[i*4+2] = (chunk_ptr[i+1] >> 16) & 0xFF; \
                            block[i*4+3] = (chunk_ptr[i+1] >> 24) & 0xFF; \
                        } \
                        uint32_t current_sig = chunk_ptr[0]; \
                        uint8_t temp_key[16]; \
                        for(int k=0; k<16; ++k) temp_key[k] = _Obf::key[k] ^ ((current_sig >> (k%4)*8) & 0xFF); \
                        aes_constexpr::DecryptBlock(block, _Obf::key); \
                        for (size_t j = 0; j < 16 && (chunk * 16 + j) < sizeof(out); ++j) \
                            out[chunk * 16 + j] = (char)block[j]; \
                    } \
                    out[sizeof(str)] = 0; \
                    std::string s(out); \
                    return s; \
                })()
    
    // ------------------------------------------------
    #pragma endregion Chunks
OPT
