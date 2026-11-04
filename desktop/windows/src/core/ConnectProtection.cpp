#include "ConnectProtection.h"

#include "Encoding.h"
#include "Json.h"
#include "Validation.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <array>
#include <memory>

namespace tlp {
namespace {
constexpr char prefix[] = "TELIPHONES-CONNECT/1:";
constexpr std::size_t saltSize = 16, nonceSize = 12, keySize = 44, tagSize = 16;
using Kdf = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
using KdfContext = std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;
using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

struct Secret {
    std::array<unsigned char, 32> bytes{};
    ~Secret() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};

void require(bool ok) {
    if (!ok) throw Error("Connect password authentication failed, or the protected credential is damaged.");
}

void derive(Secret& key, const std::string& password, unsigned char* salt) {
    require(!password.empty() && password.size() <= 1024);
    Kdf kdf(EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr), EVP_KDF_free);
    if (!kdf) throw Error("This OpenSSL build has no Argon2id provider. The protected key cannot be unlocked; no fallback is permitted.");
    KdfContext context(EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free);
    require(context != nullptr);
    // Version 1 has fixed, bounded Argon2id v1.3 parameters: 64 MiB, three passes, one lane/thread.
    unsigned int memory = 65536, iterations = 3, lanes = 1, threads = 1, version = 0x13;
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string("pass", const_cast<char*>(password.data()), password.size()),
        OSSL_PARAM_construct_octet_string("salt", salt, saltSize),
        OSSL_PARAM_construct_uint("memcost", &memory),
        OSSL_PARAM_construct_uint("iter", &iterations),
        OSSL_PARAM_construct_uint("lanes", &lanes),
        OSSL_PARAM_construct_uint("threads", &threads),
        OSSL_PARAM_construct_uint("version", &version),
        OSSL_PARAM_construct_end()
    };
    require(EVP_KDF_derive(context.get(), key.bytes.data(), key.bytes.size(), parameters) == 1);
}

std::string aad(const std::string& target) {
    require(!target.empty() && target.size() <= 256);
    return std::string(prefix) + target;
}
}  // namespace

bool ConnectProtectionAvailable() {
    Kdf kdf(EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr), EVP_KDF_free);
    return kdf != nullptr;
}

bool IsProtectedConnectKey(const std::string& stored) {
    // Unknown/corrupt formats must not be reinterpreted as unprotected credentials.
    return !IsWireGuardKey(stored);
}

std::string ProtectConnectKey(const std::string& target, const std::string& privateKey, const std::string& password) {
    require(IsWireGuardKey(privateKey));
    if (password.size() < 12 || password.size() > 1024)
        throw Error("Use a Connect password of 12 to 1024 UTF-8 bytes.");
    Bytes envelope(saltSize + nonceSize + keySize + tagSize);
    require(RAND_bytes(envelope.data(), static_cast<int>(saltSize + nonceSize)) == 1);
    Secret key;
    derive(key, password, envelope.data());
    const std::string binding = aad(target);
    CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    require(context != nullptr);
    require(EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, key.bytes.data(), envelope.data() + saltSize) == 1);
    int count = 0, finalCount = 0;
    require(EVP_EncryptUpdate(context.get(), nullptr, &count,
                             reinterpret_cast<const unsigned char*>(binding.data()), static_cast<int>(binding.size())) == 1);
    require(EVP_EncryptUpdate(context.get(), envelope.data() + saltSize + nonceSize, &count,
                             reinterpret_cast<const unsigned char*>(privateKey.data()), static_cast<int>(privateKey.size())) == 1);
    require(count == static_cast<int>(keySize));
    require(EVP_EncryptFinal_ex(context.get(), envelope.data() + saltSize + nonceSize + count, &finalCount) == 1 && finalCount == 0);
    require(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tagSize),
                               envelope.data() + saltSize + nonceSize + keySize) == 1);
    return std::string(prefix) + Base64Encode(envelope);
}

std::string OpenConnectKey(const std::string& target, const std::string& stored, const std::string& password) {
    if (!IsProtectedConnectKey(stored)) return stored;
    require(stored.compare(0, sizeof(prefix) - 1, prefix) == 0 && stored.size() < 512);
    Bytes envelope = Base64Decode(stored.substr(sizeof(prefix) - 1));
    require(envelope.size() == saltSize + nonceSize + keySize + tagSize);
    Secret key;
    derive(key, password, envelope.data());
    const std::string binding = aad(target);
    CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    require(context != nullptr);
    require(EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, key.bytes.data(), envelope.data() + saltSize) == 1);
    int count = 0, finalCount = 0;
    require(EVP_DecryptUpdate(context.get(), nullptr, &count,
                             reinterpret_cast<const unsigned char*>(binding.data()), static_cast<int>(binding.size())) == 1);
    std::array<unsigned char, keySize + 16> plaintext{};
    struct Wipe {
        decltype(plaintext)& bytes;
        ~Wipe() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
    } wipe{plaintext};
    require(EVP_DecryptUpdate(context.get(), plaintext.data(), &count, envelope.data() + saltSize + nonceSize,
                             static_cast<int>(keySize)) == 1 && count == static_cast<int>(keySize));
    require(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tagSize),
                               envelope.data() + saltSize + nonceSize + keySize) == 1);
    require(EVP_DecryptFinal_ex(context.get(), plaintext.data() + count, &finalCount) == 1 && finalCount == 0);
    std::string result(reinterpret_cast<const char*>(plaintext.data()), keySize);
    if (!IsWireGuardKey(result)) {
        OPENSSL_cleanse(result.data(), result.size());
        require(false);
    }
    return result;
}

}  // namespace tlp
