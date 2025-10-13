#include <sstream>
#include <iomanip>

#include <mailio/sha256.hpp>

#if defined(MAILIO_HAVE_OPENSSL)
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

namespace mailio
{

static std::string to_hex(const unsigned char* data, std::size_t len)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i)
        oss << std::setw(2) << static_cast<int>(data[i]);
    return oss.str();
}

std::string sha256_hex(std::string_view data)
{
    auto bytes = sha256_bytes(data.data(), data.size());
    return to_hex(bytes.data(), bytes.size());
}

std::string sha256_hex(const void* data, std::size_t size)
{
    auto bytes = sha256_bytes(data, size);
    return to_hex(bytes.data(), bytes.size());
}

std::string sha256_hex(const std::vector<unsigned char>& data)
{
    auto bytes = sha256_bytes(data.data(), data.size());
    return to_hex(bytes.data(), bytes.size());
}

std::array<unsigned char, 32> sha256_bytes(std::string_view data)
{
    return sha256_bytes(data.data(), data.size());
}

std::array<unsigned char, 32> sha256_bytes(const void* data, std::size_t size)
{
    std::array<unsigned char, 32> digest{};

#if defined(MAILIO_HAVE_OPENSSL)
    // Prefer high-level EVP interface for forward-compatibility
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");

    const EVP_MD* md = EVP_sha256();
    if (!md)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_sha256 unavailable");
    }

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    if (size > 0 && data != nullptr)
    {
        if (EVP_DigestUpdate(ctx, data, size) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("EVP_DigestUpdate failed");
        }
    }
    unsigned int out_len = static_cast<unsigned int>(digest.size());
    if (EVP_DigestFinal_ex(ctx, digest.data(), &out_len) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }
    EVP_MD_CTX_free(ctx);
    // Ensure we got expected size
    if (out_len != digest.size())
        throw std::runtime_error("Unexpected SHA-256 digest length");
    return digest;
#else
    (void)data; (void)size;
    throw std::runtime_error("OpenSSL not available: SHA-256 requires OpenSSL");
#endif
}

std::array<unsigned char, 32> sha256_bytes(const std::vector<unsigned char>& data)
{
    return sha256_bytes(data.data(), data.size());
}

} // namespace mailio
