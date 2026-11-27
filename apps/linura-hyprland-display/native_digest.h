#pragma once

#include <openssl/evp.h>
#include <array>
#include <optional>
#include <string>
#include <string_view>

namespace Linura::HyprlandDisplay {
// Fixed SHA-256 for native comparison witnesses. A digest grants no authority.
inline std::optional<std::string> nativeSha256(std::string_view bytes)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> hash{};
    unsigned int written = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), hash.data(), &written, EVP_sha256(), nullptr) != 1 ||
        written != 32)
        return std::nullopt;
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (unsigned int i = 0; i < written; ++i) {
        result += digits[hash[i] >> 4U];
        result += digits[hash[i] & 15U];
    }
    return result;
}
} // namespace Linura::HyprlandDisplay
