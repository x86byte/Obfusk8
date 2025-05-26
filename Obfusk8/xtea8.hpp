#pragma once

#include <cstdint>
#include <string>
#include <array>

#pragma region XTEAstuff
// ------------------------------------------------

    namespace xtea_en8de {
        constexpr void xtea_encipher(uint32_t* v, const uint32_t* key, int num_rounds = 32) {
            uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
            for (int i = 0; i < num_rounds; ++i) {
                v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
                sum += delta;
                v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
            }
            v[0] = v0; v[1] = v1;
        }
        constexpr void xtea_decipher(uint32_t* v, const uint32_t* key, int num_rounds = 32) {
            uint32_t v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * num_rounds;
            for (int i = 0; i < num_rounds; ++i) {
                v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
                sum -= delta;
                v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
            }
            v[0] = v0; v[1] = v1;
        }
    } 

    using namespace xtea_en8de;

    #define XTEA_MIX(str, line) (uint32_t)(((sizeof(str) ^ ((line) * 0x314159)) ^ (__FILE__[0] * 0x271828)) | 1)
    #define XTEA_KEY0(str, line) (0xA3B1BAC6u ^ XTEA_MIX(str, line))
    #define XTEA_KEY1(str, line) (0x56AA3350u ^ XTEA_MIX(str, line))
    #define XTEA_KEY2(str, line) (0x677D9197u ^ XTEA_MIX(str, line))
    #define XTEA_KEY3(str, line) (0xB27022DCu ^ XTEA_MIX(str, line))

    template <size_t N, uint32_t K0, uint32_t K1, uint32_t K2, uint32_t K3>
    struct _XTEA8ObfStrs {
        static constexpr uint32_t key[4] = { K0, K1, K2, K3 };
        static constexpr std::array<uint32_t, ((N + 7) / 8 * 2)> encrypt(const char (&plain)[N]) {
            std::array<uint32_t, ((N + 7) / 8 * 2)> enc{};
            for (size_t i = 0; i < (N + 7) / 8; ++i) {
                uint32_t v[2] = {0, 0};
                for (size_t j = 0; j < 4 && (i * 8 + j) < N; ++j)
                    v[0] |= static_cast<uint8_t>(plain[i * 8 + j]) << (j * 8);
                for (size_t j = 0; j < 4 && (i * 8 + 4 + j) < N; ++j)
                    v[1] |= static_cast<uint8_t>(plain[i * 8 + 4 + j]) << (j * 8);
                xtea_encipher(v, key);
                enc[i * 2] = v[0];
                enc[i * 2 + 1] = v[1];
            }
            return enc;
        }
    };

    #define CONCAT2(a,b) a##b
    #define CONCAT(a,b) CONCAT2(a,b)

// ------------------------------------------------
#pragma endregion XTEAstuff

#pragma region Chunks
// ------------------------------------------------

    #pragma region MSVC_sections
    // ------------------------------------------------

        #define PACKER_SECTION_4 ".arch"
        #define PACKER_SECTION_6 ".xpdata"
        #define PACKER_SECTION_9 ".PECompac"
        #define PACKER_SECTION_3 ".xtls"
        #define PACKER_SECTION_0 ".themida"
        #define PACKER_SECTION_5 ".vmp0"
        #define PACKER_SECTION_1 ".vmp1"
        #define PACKER_SECTION_7 ".vmp2"
        #define PACKER_SECTION_23 ".vmp3"
        #define PACKER_SECTION_24 ".vmp4"
        #define PACKER_SECTION_25 ".vmp5"
        #define PACKER_SECTION_26 ".vmp6"
        #define PACKER_SECTION_27 ".vmp7"
        #define PACKER_SECTION_28 ".vmp8"
        #define PACKER_SECTION_8 ".enigma1"
        #define PACKER_SECTION_2 ".enigma2"
        #define PACKER_SECTION_10 ".dsstext"
        #define PACKER_SECTION_11 ".UPX0"
        #define PACKER_SECTION_12 ".UPX1"
        #define PACKER_SECTION_13 ".UPX2"
        #define PACKER_SECTION_14 ".aspack"
        #define PACKER_SECTION_15 ".nsp0"
        #define PACKER_SECTION_16 ".nsp1"
        #define PACKER_SECTION_17 ".FSG!"
        #define PACKER_SECTION_18 ".pec1"
        #define PACKER_SECTION_19 ".pec2"
        #define PACKER_SECTION_20 ".petite"
        #define PACKER_SECTION_21 ".mpress1"
        #define PACKER_SECTION_22 ".mpress2"

        //#define PACKER_SECTION_COUNT 29

        #define PICK_SECTION(idx) PACKER_SECTION_##idx

        #if defined(_MSC_VER)
            #pragma section(".arch", read, write)
            #pragma section(".xpdata", read, write)
            #pragma section(".PECompac", read, write)
            #pragma section(".xtls", read, write)
            #pragma section(".themida", read, write)
            #pragma section(".vmp0", read, write)
            #pragma section(".vmp1", read, write)
            #pragma section(".vmp2", read, write)
            #pragma section(".vmp3", read, write)
            #pragma section(".vmp4", read, write)
            #pragma section(".vmp5", read, write)
            #pragma section(".vmp6", read, write)
            #pragma section(".vmp7", read, write)
            #pragma section(".vmp8", read, write)
            #pragma section(".enigma1", read, write)
            #pragma section(".enigma2", read, write)
            #pragma section(".dsstext", read, write)
            #pragma section(".UPX0", read, write)
            #pragma section(".UPX1", read, write)
            #pragma section(".UPX2", read, write)
            #pragma section(".aspack", read, write)
            #pragma section(".nsp0", read, write)
            #pragma section(".nsp1", read, write)
            #pragma section(".FSG!", read, write)
            #pragma section(".pec1", read, write)
            #pragma section(".pec2", read, write)
            #pragma section(".petite", read, write)
            #pragma section(".mpress1", read, write)
            #pragma section(".mpress2", read, write)
        #endif

        #if defined(_MSC_VER)
            #define DECLARE_SECTION(secname) __pragma(section(secname, read, write))
            #define SECTION_ATTR_SEC(secname) __declspec(allocate(secname))
        #endif

        #pragma region g_sigs
        // ------------------------------------------------

            #define SIGNATURE_UPX     0x21585055  // "UPX!"
            #define SIGNATURE_VMP     0x504d565b  // "[VMP"
            #define SIGNATURE_ENIGMA  0x47494e45  // "ENIG"
            #define SIGNATURE_THEMIDA 0x4944454d  // "MEDI"
            #define SIGNATURE_FSG     0x21475346  // "FSG!"
            #define SIGNATURE_ASPACK  0x4b434150  // "PACK"
            #define SIGNATURE_NSPACK  0x4b43414e  // "NACK"
            #define SIGNATURE_MPRESS  0x53534552  // "RESS"

        // ------------------------------------------------
        #pragma endregion g_sigs

    // ------------------------------------------------
    #pragma endregion MSVC_sections


    #define OBFUSCATE_STRING(str) \
        ([]() -> std::string { \
            using _Obf = _XTEA8ObfStrs<sizeof(str), \
                XTEA_KEY0(str, __LINE__), XTEA_KEY1(str, __LINE__), XTEA_KEY2(str, __LINE__), XTEA_KEY3(str, __LINE__)>; \
            constexpr auto encrypted = _Obf::encrypt(str); \
            DECLARE_SECTION(PICK_SECTION(0)) \
            static SECTION_ATTR_SEC(PICK_SECTION(0)) uint32_t CONCAT(_obfstr_chunk0_, __LINE__)[3] = { SIGNATURE_UPX + 0xFFFF,      encrypted[0],  encrypted[1]  }; \
            DECLARE_SECTION(PICK_SECTION(1)) \
            static SECTION_ATTR_SEC(PICK_SECTION(1)) uint32_t CONCAT(_obfstr_chunk1_, __LINE__)[3] = { SIGNATURE_THEMIDA,  encrypted[2],  encrypted[3]  }; \
            DECLARE_SECTION(PICK_SECTION(2)) \
            static SECTION_ATTR_SEC(PICK_SECTION(2)) uint32_t CONCAT(_obfstr_chunk2_, __LINE__)[3] = { SIGNATURE_ENIGMA,   encrypted[4],  encrypted[5]  }; \
            DECLARE_SECTION(PICK_SECTION(3)) \
            static SECTION_ATTR_SEC(PICK_SECTION(3)) uint32_t CONCAT(_obfstr_chunk3_, __LINE__)[3] = { SIGNATURE_VMP,      encrypted[6],  encrypted[7]  }; \
            DECLARE_SECTION(PICK_SECTION(4)) \
            static SECTION_ATTR_SEC(PICK_SECTION(4)) uint32_t CONCAT(_obfstr_chunk4_, __LINE__)[3] = { SIGNATURE_FSG,      encrypted[8],  encrypted[9]  }; \
            DECLARE_SECTION(PICK_SECTION(5)) \
            static SECTION_ATTR_SEC(PICK_SECTION(5)) uint32_t CONCAT(_obfstr_chunk5_, __LINE__)[3] = { SIGNATURE_ASPACK,   encrypted[10], encrypted[11] }; \
            DECLARE_SECTION(PICK_SECTION(6)) \
            static SECTION_ATTR_SEC(PICK_SECTION(6)) uint32_t CONCAT(_obfstr_chunk6_, __LINE__)[3] = { SIGNATURE_NSPACK,   encrypted[12], encrypted[13] }; \
            DECLARE_SECTION(PICK_SECTION(7)) \
            static SECTION_ATTR_SEC(PICK_SECTION(7)) uint32_t CONCAT(_obfstr_chunk7_, __LINE__)[3] = { SIGNATURE_MPRESS,   encrypted[14], encrypted[15] }; \
            DECLARE_SECTION(PICK_SECTION(8)) \
            static SECTION_ATTR_SEC(PICK_SECTION(8)) uint32_t CONCAT(_obfstr_chunk8_, __LINE__)[3] = { SIGNATURE_UPX + 0xFFFF,      encrypted[16], encrypted[17] }; \
            DECLARE_SECTION(PICK_SECTION(9)) \
            static SECTION_ATTR_SEC(PICK_SECTION(9)) uint32_t CONCAT(_obfstr_chunk9_, __LINE__)[3] = { SIGNATURE_THEMIDA,  encrypted[18], encrypted[19] }; \
            DECLARE_SECTION(PICK_SECTION(10)) \
            static SECTION_ATTR_SEC(PICK_SECTION(10)) uint32_t CONCAT(_obfstr_chunk10_, __LINE__)[3] = { SIGNATURE_ENIGMA,  encrypted[20], encrypted[21] }; \
            DECLARE_SECTION(PICK_SECTION(11)) \
            static SECTION_ATTR_SEC(PICK_SECTION(11)) uint32_t CONCAT(_obfstr_chunk11_, __LINE__)[3] = { SIGNATURE_VMP,     encrypted[22], encrypted[23] }; \
            DECLARE_SECTION(PICK_SECTION(12)) \
            static SECTION_ATTR_SEC(PICK_SECTION(12)) uint32_t CONCAT(_obfstr_chunk12_, __LINE__)[3] = { SIGNATURE_FSG,     encrypted[24], encrypted[25] }; \
            DECLARE_SECTION(PICK_SECTION(13)) \
            static SECTION_ATTR_SEC(PICK_SECTION(13)) uint32_t CONCAT(_obfstr_chunk13_, __LINE__)[3] = { SIGNATURE_ASPACK,  encrypted[26], encrypted[27] }; \
            DECLARE_SECTION(PICK_SECTION(14)) \
            static SECTION_ATTR_SEC(PICK_SECTION(14)) uint32_t CONCAT(_obfstr_chunk14_, __LINE__)[3] = { SIGNATURE_NSPACK,  encrypted[28], encrypted[29] }; \
            DECLARE_SECTION(PICK_SECTION(15)) \
            static SECTION_ATTR_SEC(PICK_SECTION(15)) uint32_t CONCAT(_obfstr_chunk15_, __LINE__)[3] = { SIGNATURE_MPRESS,  encrypted[30], encrypted[31] }; \
            DECLARE_SECTION(PICK_SECTION(16)) \
            static SECTION_ATTR_SEC(PICK_SECTION(16)) uint32_t CONCAT(_obfstr_chunk16_, __LINE__)[3] = { SIGNATURE_UPX + 0xFFFF,     encrypted[32], encrypted[33] }; \
            DECLARE_SECTION(PICK_SECTION(17)) \
            static SECTION_ATTR_SEC(PICK_SECTION(17)) uint32_t CONCAT(_obfstr_chunk17_, __LINE__)[3] = { SIGNATURE_THEMIDA, encrypted[34], encrypted[35] }; \
            DECLARE_SECTION(PICK_SECTION(18)) \
            static SECTION_ATTR_SEC(PICK_SECTION(18)) uint32_t CONCAT(_obfstr_chunk18_, __LINE__)[3] = { SIGNATURE_ENIGMA,  encrypted[36], encrypted[37] }; \
            DECLARE_SECTION(PICK_SECTION(19)) \
            static SECTION_ATTR_SEC(PICK_SECTION(19)) uint32_t CONCAT(_obfstr_chunk19_, __LINE__)[3] = { SIGNATURE_VMP,     encrypted[38], encrypted[39] }; \
            DECLARE_SECTION(PICK_SECTION(20)) \
            static SECTION_ATTR_SEC(PICK_SECTION(20)) uint32_t CONCAT(_obfstr_chunk20_, __LINE__)[3] = { SIGNATURE_FSG,     encrypted[40], encrypted[41] }; \
            DECLARE_SECTION(PICK_SECTION(21)) \
            static SECTION_ATTR_SEC(PICK_SECTION(21)) uint32_t CONCAT(_obfstr_chunk21_, __LINE__)[3] = { SIGNATURE_ASPACK,  encrypted[42], encrypted[43] }; \
            DECLARE_SECTION(PICK_SECTION(22)) \
            static SECTION_ATTR_SEC(PICK_SECTION(22)) uint32_t CONCAT(_obfstr_chunk22_, __LINE__)[3] = { SIGNATURE_NSPACK,  encrypted[44], encrypted[45] }; \
            DECLARE_SECTION(PICK_SECTION(23)) \
            static SECTION_ATTR_SEC(PICK_SECTION(23)) uint32_t CONCAT(_obfstr_chunk23_, __LINE__)[3] = { SIGNATURE_MPRESS,  encrypted[46], encrypted[47] }; \
            DECLARE_SECTION(PICK_SECTION(24)) \
            static SECTION_ATTR_SEC(PICK_SECTION(24)) uint32_t CONCAT(_obfstr_chunk24_, __LINE__)[3] = { SIGNATURE_UPX + 0xFFFF,     encrypted[48], encrypted[49] }; \
            DECLARE_SECTION(PICK_SECTION(25)) \
            static SECTION_ATTR_SEC(PICK_SECTION(25)) uint32_t CONCAT(_obfstr_chunk25_, __LINE__)[3] = { SIGNATURE_THEMIDA, encrypted[50], encrypted[51] }; \
            DECLARE_SECTION(PICK_SECTION(26)) \
            static SECTION_ATTR_SEC(PICK_SECTION(26)) uint32_t CONCAT(_obfstr_chunk26_, __LINE__)[3] = { SIGNATURE_ENIGMA,  encrypted[52], encrypted[53] }; \
            DECLARE_SECTION(PICK_SECTION(27)) \
            static SECTION_ATTR_SEC(PICK_SECTION(27)) uint32_t CONCAT(_obfstr_chunk27_, __LINE__)[3] = { SIGNATURE_VMP,     encrypted[54], encrypted[55] }; \
            char out[sizeof(str)]; \
            for (int chunk = 0; chunk < 28; ++chunk) { \
                uint32_t* chunk_ptr; \
                switch(chunk) { \
                    case 0: chunk_ptr = CONCAT(_obfstr_chunk0_, __LINE__); break; \
                    case 1: chunk_ptr = CONCAT(_obfstr_chunk1_, __LINE__); break; \
                    case 2: chunk_ptr = CONCAT(_obfstr_chunk2_, __LINE__); break; \
                    case 3: chunk_ptr = CONCAT(_obfstr_chunk3_, __LINE__); break; \
                    case 4: chunk_ptr = CONCAT(_obfstr_chunk4_, __LINE__); break; \
                    case 5: chunk_ptr = CONCAT(_obfstr_chunk5_, __LINE__); break; \
                    case 6: chunk_ptr = CONCAT(_obfstr_chunk6_, __LINE__); break; \
                    case 7: chunk_ptr = CONCAT(_obfstr_chunk7_, __LINE__); break; \
                    case 8: chunk_ptr = CONCAT(_obfstr_chunk8_, __LINE__); break; \
                    case 9: chunk_ptr = CONCAT(_obfstr_chunk9_, __LINE__); break; \
                    case 10: chunk_ptr = CONCAT(_obfstr_chunk10_, __LINE__); break; \
                    case 11: chunk_ptr = CONCAT(_obfstr_chunk11_, __LINE__); break; \
                    case 12: chunk_ptr = CONCAT(_obfstr_chunk12_, __LINE__); break; \
                    case 13: chunk_ptr = CONCAT(_obfstr_chunk13_, __LINE__); break; \
                    case 14: chunk_ptr = CONCAT(_obfstr_chunk14_, __LINE__); break; \
                    case 15: chunk_ptr = CONCAT(_obfstr_chunk15_, __LINE__); break; \
                    case 16: chunk_ptr = CONCAT(_obfstr_chunk16_, __LINE__); break; \
                    case 17: chunk_ptr = CONCAT(_obfstr_chunk17_, __LINE__); break; \
                    case 18: chunk_ptr = CONCAT(_obfstr_chunk18_, __LINE__); break; \
                    case 19: chunk_ptr = CONCAT(_obfstr_chunk19_, __LINE__); break; \
                    case 20: chunk_ptr = CONCAT(_obfstr_chunk20_, __LINE__); break; \
                    case 21: chunk_ptr = CONCAT(_obfstr_chunk21_, __LINE__); break; \
                    case 22: chunk_ptr = CONCAT(_obfstr_chunk22_, __LINE__); break; \
                    case 23: chunk_ptr = CONCAT(_obfstr_chunk23_, __LINE__); break; \
                    case 24: chunk_ptr = CONCAT(_obfstr_chunk24_, __LINE__); break; \
                    case 25: chunk_ptr = CONCAT(_obfstr_chunk25_, __LINE__); break; \
                    case 26: chunk_ptr = CONCAT(_obfstr_chunk26_, __LINE__); break; \
                    case 27: chunk_ptr = CONCAT(_obfstr_chunk27_, __LINE__); break; \
                    default: chunk_ptr = nullptr; \
                } \
                if (!chunk_ptr) break; \
                uint32_t v[2] = { chunk_ptr[1], chunk_ptr[2] }; \
                xtea_decipher(v, _Obf::key); \
                for (size_t j = 0; j < 4 && (chunk * 8 + j) < sizeof(str); ++j) \
                    out[chunk * 8 + j] = static_cast<char>((v[0] >> (j * 8)) & 0xFF); \
                for (size_t j = 0; j < 4 && (chunk * 8 + 4 + j) < sizeof(str); ++j) \
                    out[chunk * 8 + 4 + j] = static_cast<char>((v[1] >> (j * 8)) & 0xFF); \
            } \
            out[sizeof(str) - 1] = 0; \
            std::string s(out, sizeof(str) - 1); \
            return s; \
        })()

// ------------------------------------------------
#pragma endregion Chunks