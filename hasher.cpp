#include "hasher.h"

#include <array>
#include <fstream>
#include <iomanip>
#include <memory>
#include <openssl/evp.h>
#include <sstream>

std::optional<std::string> Hasher::sha256File(const std::filesystem::path& path, std::string& errorMessage) const {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        errorMessage = "Unable to open file for hashing";
        return std::nullopt;
    }

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!context) {
        errorMessage = "Unable to allocate OpenSSL digest context";
        return std::nullopt;
    }

    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        errorMessage = "EVP_DigestInit_ex failed";
        return std::nullopt;
    }

    std::array<char, 4096> buffer{};
    while (input.good()) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize bytesRead = input.gcount();

        if (bytesRead > 0) {
            if (EVP_DigestUpdate(
                    context.get(),
                    buffer.data(),
                    static_cast<std::size_t>(bytesRead)) != 1) {
                errorMessage = "EVP_DigestUpdate failed";
                return std::nullopt;
            }
        }
    }

    if (!input.eof()) {
        errorMessage = "Read error while hashing file";
        return std::nullopt;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLength = 0;
    if (EVP_DigestFinal_ex(context.get(), digest, &digestLength) != 1) {
        errorMessage = "EVP_DigestFinal_ex failed";
        return std::nullopt;
    }

    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < digestLength; ++i) {
        hex << std::setw(2) << static_cast<unsigned int>(digest[i]);
    }

    return hex.str();
}
