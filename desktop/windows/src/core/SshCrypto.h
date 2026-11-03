#pragma once

#include "Encoding.h"
#include <memory>

namespace tlp {

class SshSigningKey {
public:
    enum class Purpose { Session, Workstation };
    explicit SshSigningKey(Purpose purpose = Purpose::Session);
    explicit SshSigningKey(const Bytes& seed);
    ~SshSigningKey();
    SshSigningKey(const SshSigningKey&) = delete;
    SshSigningKey& operator=(const SshSigningKey&) = delete;
    std::string publicKey() const;
    Bytes sign(const Bytes& message) const;
    // Export is only for the permanent workstation identity's encrypted store.
    Bytes identitySeed() const;
    void destroy();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

Bytes SshField(const Bytes& value);
Bytes SshField(const std::string& value);
Bytes SshJoin(std::initializer_list<Bytes> fields);
Bytes SshNumber(std::uint32_t value);
class SshWireReader {
public:
    explicit SshWireReader(const Bytes& value) : value_(value) {}
    std::uint32_t number();
    Bytes field();
    std::string text();
    bool done() const { return offset_ == value_.size(); }
    std::size_t offset() const { return offset_; }
private:
    const Bytes& value_;
    std::size_t offset_ = 0;
};

Bytes WorkstationIdentitySeed(const std::string& stored);
std::string SignSshChallenge(const SshSigningKey& identity, const std::string& message);
void VerifySshCertificateSignature(const std::string& certificate, const std::string& ca);
// Restrict the agent to a userauth request for this exact user and certificate.
void ValidateSshAuthentication(const Bytes& message, const std::string& user, const Bytes& certificate, const Bytes& hostKey);

class SshAgentProtocol {
public:
    SshAgentProtocol(std::unique_ptr<SshSigningKey> key, const std::string& certificate,
                     const std::string& user, const std::string& hostKey);
    Bytes reply(const Bytes& request);
    bool destroyed() const { return key_ == nullptr; }
    void destroy() { key_.reset(); }
private:
    std::unique_ptr<SshSigningKey> key_;
    Bytes certificate_;
    Bytes hostKey_;
    std::string user_;
};

} // namespace tlp
