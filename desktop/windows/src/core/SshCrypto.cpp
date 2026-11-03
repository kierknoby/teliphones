#include "SshCrypto.h"
#include "Json.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <array>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

namespace tlp {
namespace {
Bytes blob(const std::string& line) {
    const auto space = line.find(' ');
    if (space == std::string::npos) throw Error("Invalid SSH public encoding.");
    const auto end = line.find_first_of(" \r\n", space + 1);
    return Base64Decode(line.substr(space + 1, end - space - 1));
}
void require(bool ok, const char* message) {
    if (!ok) throw Error(message);
}
using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
}

Bytes SshJoin(std::initializer_list<Bytes> fields) {
    Bytes out;
    for (const auto& field : fields) out.insert(out.end(), field.begin(), field.end());
    return out;
}
Bytes SshNumber(std::uint32_t value) {
    return {static_cast<std::uint8_t>(value >> 24), static_cast<std::uint8_t>(value >> 16),
            static_cast<std::uint8_t>(value >> 8), static_cast<std::uint8_t>(value)};
}
Bytes SshField(const Bytes& value) {
    if (value.size() > 1024 * 1024) throw Error("Oversized SSH field.");
    return SshJoin({SshNumber(static_cast<std::uint32_t>(value.size())), value});
}
Bytes SshField(const std::string& value) { return SshField(Bytes(value.begin(), value.end())); }
std::uint32_t SshWireReader::number() {
    if (value_.size() - offset_ < 4) throw Error("Truncated SSH encoding.");
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) value = (value << 8) | value_[offset_++];
    return value;
}
Bytes SshWireReader::field() {
    const auto size = number();
    if (size > value_.size() - offset_) throw Error("Truncated SSH field.");
    Bytes result(value_.begin() + offset_, value_.begin() + offset_ + size);
    offset_ += size;
    return result;
}
std::string SshWireReader::text() {
    const auto bytes = field();
    return std::string(bytes.begin(), bytes.end());
}

struct SshSigningKey::Impl {
    unsigned char* seed = nullptr;
    Purpose purpose;
    explicit Impl(Purpose value) : purpose(value) {
        static const bool configured = OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr) == 1;
        if (!configured) throw Error("Unable to initialise the SSH cryptographic provider.");
#ifdef _WIN32
        seed = static_cast<unsigned char*>(VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!seed) throw Error("Unable to allocate private SSH seed memory.");
        if (!VirtualLock(seed, 4096)) {
            VirtualFree(seed, 0, MEM_RELEASE);
            throw Error("Unable to lock SSH seed memory.");
        }
#else
        seed = static_cast<unsigned char*>(OPENSSL_zalloc(32));
        if (!seed) throw Error("Unable to allocate SSH seed memory.");
#endif
    }
    ~Impl() {
        OPENSSL_cleanse(seed, 32);
#ifdef _WIN32
        VirtualUnlock(seed, 4096);
        VirtualFree(seed, 0, MEM_RELEASE);
#else
        OPENSSL_free(seed);
#endif
    }
    Key import() const {
        Key key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed, 32), EVP_PKEY_free);
        require(key != nullptr, "Unable to initialise the SSH signing key.");
        return key;
    }
};
SshSigningKey::SshSigningKey(Purpose purpose) : impl_(std::make_unique<Impl>(purpose)) {
    require(RAND_priv_bytes(impl_->seed, 32) == 1, "SSH random generation failed.");
}
SshSigningKey::SshSigningKey(const Bytes& seed) : impl_(std::make_unique<Impl>(Purpose::Workstation)) {
    require(seed.size() == 32, "Invalid workstation identity seed.");
    std::copy(seed.begin(), seed.end(), impl_->seed);
}
SshSigningKey::~SshSigningKey() = default;
void SshSigningKey::destroy() { impl_.reset(); }
Bytes SshSigningKey::identitySeed() const {
    require(impl_ && impl_->purpose == Purpose::Workstation, "SSH session credentials cannot be exported.");
    return Bytes(impl_->seed, impl_->seed + 32);
}
std::string SshSigningKey::publicKey() const {
    require(impl_ != nullptr, "SSH credential has been destroyed.");
    Bytes publicKey(32);
    std::size_t size = publicKey.size();
    const auto key = impl_->import();
    require(EVP_PKEY_get_raw_public_key(key.get(), publicKey.data(), &size) == 1 && size == 32, "SSH public key generation failed.");
    return "ssh-ed25519 " + Base64Encode(SshJoin({SshField(std::string("ssh-ed25519")), SshField(publicKey)}));
}
Bytes SshSigningKey::sign(const Bytes& message) const {
    require(impl_ != nullptr, "SSH credential has been destroyed.");
    const auto key = impl_->import();
    Context context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    require(context && EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, key.get()) == 1, "SSH signing setup failed.");
    Bytes signature(64);
    std::size_t size = signature.size();
    require(EVP_DigestSign(context.get(), signature.data(), &size, message.data(), message.size()) == 1 && size == 64,
            "SSH signing failed.");
    return SshJoin({SshField(std::string("ssh-ed25519")), SshField(signature)});
}

Bytes WorkstationIdentitySeed(const std::string& stored) {
    const std::string binaryPrefix = "teliphones-ed25519-seed/2:";
    if (stored.compare(0, binaryPrefix.size(), binaryPrefix) == 0) {
        require(stored.size() == binaryPrefix.size() + 32, "Invalid saved workstation identity seed.");
        return Bytes(stored.begin() + binaryPrefix.size(), stored.end());
    }
    const std::string prefix = "teliphones-ed25519-seed/1:";
    if (stored.compare(0, prefix.size(), prefix) == 0) {
        auto seed = Base64Decode(stored.substr(prefix.size()));
        if (seed.size() != 32) throw Error("Invalid saved workstation identity.");
        return seed;
    }
    const std::string begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const std::string end = "-----END OPENSSH PRIVATE KEY-----";
    const auto first = stored.find(begin), last = stored.find(end);
    if (first != 0 || last == std::string::npos) throw Error("Unsupported saved workstation identity.");
    auto encoded = stored.substr(begin.size(), last - begin.size());
    struct ClearText { std::string& text; ~ClearText() { OPENSSL_cleanse(text.data(), text.size()); } } clearEncoded{encoded};
    encoded.erase(std::remove_if(encoded.begin(), encoded.end(), [](char c) { return c == '\r' || c == '\n'; }), encoded.end());
    auto decoded = Base64Decode(encoded);
    struct Wipe {
        Bytes& bytes;
        ~Wipe() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
    } wipe{decoded};
    const std::string magic("openssh-key-v1\0", 15);
    require(decoded.size() >= magic.size() && std::equal(magic.begin(), magic.end(), decoded.begin()), "Invalid OpenSSH identity.");
    Bytes body(decoded.begin() + magic.size(), decoded.end());
    Wipe wipeBody{body};
    SshWireReader reader(body);
    require(reader.text() == "none" && reader.text() == "none" && reader.field().empty() && reader.number() == 1,
            "Unsupported encrypted or multi-key workstation identity.");
    reader.field();
    auto privatePart = reader.field();
    Wipe wipePrivate{privatePart};
    require(reader.done(), "Unexpected workstation identity data.");
    SshWireReader key(privatePart);
    const auto check = key.number();
    require(key.number() == check && key.text() == "ssh-ed25519", "Invalid Ed25519 workstation identity.");
    const auto publicKey = key.field();
    auto secret = key.field();
    Wipe wipeSecret{secret};
    require(publicKey.size() == 32 && secret.size() == 64 &&
            std::equal(publicKey.begin(), publicKey.end(), secret.begin() + 32), "Invalid private identity structure.");
    return Bytes(secret.begin(), secret.begin() + 32);
}

std::string SignSshChallenge(const SshSigningKey& identity, const std::string& message) {
    const auto hash = Sha256(Bytes(message.begin(), message.end()));
    const Bytes magic{'S','S','H','S','I','G'};
    const auto fields = SshJoin({SshField(std::string("teliphones-ssh")), SshField(std::string()),
                                SshField(std::string("sha256"))});
    const auto data = SshJoin({magic, fields, SshField(Bytes(hash.begin(), hash.end()))});
    auto encoded = Base64Encode(SshJoin({magic, SshNumber(1), SshField(blob(identity.publicKey())), fields,
                                       SshField(identity.sign(data))}));
    std::string armor = "-----BEGIN SSH SIGNATURE-----\n";
    for (std::size_t i = 0; i < encoded.size(); i += 70) armor += encoded.substr(i, 70) + "\n";
    return armor + "-----END SSH SIGNATURE-----\n";
}

void VerifySshCertificateSignature(const std::string& certificate, const std::string& ca) {
    const auto bytes = blob(certificate);
    SshWireReader reader(bytes);
    require(reader.text() == "ssh-ed25519-cert-v01@openssh.com", "Unsupported SSH certificate.");
    // nonce, key, serial, type, ID, principals, validity, options, extensions, reserved, CA
    reader.field(); reader.field();
    reader.number(); reader.number(); reader.number();
    reader.field(); reader.field();
    reader.number(); reader.number(); reader.number(); reader.number();
    reader.field(); reader.field(); reader.field();
    require(reader.field() == blob(ca), "SSH certificate authority differs from the paired authority.");
    const auto signedSize = reader.offset();
    const auto signature = reader.field();
    require(reader.done(), "Trailing SSH certificate data.");
    SshWireReader sig(signature);
    require(sig.text() == "ssh-ed25519", "Unsupported SSH certificate signature.");
    const auto raw = sig.field();
    require(sig.done() && raw.size() == 64, "Invalid SSH certificate signature.");
    const auto caBlob = blob(ca);
    SshWireReader caReader(caBlob);
    require(caReader.text() == "ssh-ed25519", "Invalid pinned SSH CA.");
    const auto caKey = caReader.field();
    require(caReader.done() && caKey.size() == 32, "Invalid pinned SSH CA.");
    Key publicKey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, caKey.data(), caKey.size()), EVP_PKEY_free);
    Context context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    require(publicKey && context && EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, publicKey.get()) == 1 &&
            EVP_DigestVerify(context.get(), raw.data(), raw.size(), bytes.data(), signedSize) == 1,
            "SSH certificate digital signature verification failed.");
}

void ValidateSshAuthentication(const Bytes& message, const std::string& user, const Bytes& certificate, const Bytes& hostKey) {
    SshWireReader reader(message);
    const auto session = reader.field();
    require(session.size() >= 16 && session.size() <= 64 && reader.offset() < message.size() &&
            message[reader.offset()] == 50, "Only SSH user authentication may be signed.");
    Bytes tail(message.begin() + reader.offset() + 1, message.end());
    SshWireReader auth(tail);
    require(auth.text() == user && auth.text() == "ssh-connection", "SSH authentication account mismatch.");
    const auto method = auth.text();
    require(method == "publickey" || method == "publickey-hostbound-v00@openssh.com", "Unsupported SSH authentication method.");
    const auto offset = auth.offset();
    require(offset < tail.size() && tail[offset] == 1, "Invalid SSH authentication request.");
    Bytes fields(tail.begin() + offset + 1, tail.end());
    SshWireReader key(fields);
    require(key.text() == "ssh-ed25519-cert-v01@openssh.com" && key.field() == certificate,
            "SSH authentication is not bound to this session certificate.");
    if (method != "publickey") require(!hostKey.empty() && key.field() == hostKey, "SSH hostbound key differs from the paired host.");
    require(key.done(), "Unexpected SSH authentication fields.");
}

SshAgentProtocol::SshAgentProtocol(std::unique_ptr<SshSigningKey> key, const std::string& certificate,
                                 const std::string& user, const std::string& hostKey)
    : key_(std::move(key)), certificate_(blob(certificate)), hostKey_(blob(hostKey)), user_(user) {
    require(key_ != nullptr, "Missing SSH session signing key.");
}

Bytes SshAgentProtocol::reply(const Bytes& request) {
    require(!request.empty() && request.size() <= 16384, "Invalid SSH agent request size.");
    if (!key_) return Bytes{5};
    if (request.size() == 1 && request[0] == 11) {
        return SshJoin({Bytes{12}, SshNumber(1), SshField(certificate_), SshField(std::string("TELIPHONES session"))});
    }
    if (request[0] != 13) return Bytes{5};
    Bytes body(request.begin() + 1, request.end());
    SshWireReader reader(body);
    const auto key = reader.field(), message = reader.field();
    const auto flags = reader.number();
    require(reader.done() && flags == 0 && key == certificate_, "SSH agent signing key mismatch.");
    ValidateSshAuthentication(message, user_, certificate_, hostKey_);
    const auto signature = key_->sign(message);
    key_.reset();
    return SshJoin({Bytes{14}, SshField(signature)});
}
} // namespace tlp
