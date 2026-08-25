// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#pragma once

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <string>
#include <vector>

namespace jsp {

// RAII holder for the signer identity: end-entity certificate, its private key
// (which may live in software or on a PKCS#11 token), and any CA chain certs.
class Keystore {
public:
    // Software keystore from a PKCS#12 (.p12/.pfx) file.
    static Keystore loadPkcs12(const std::string& path, const std::string& password);

    // Hardware/smartcard keystore via a PKCS#11 module (.so/.dll). `pin` is the
    // token PIN; `keyId` optionally selects a key/cert by label or hex id.
    // Requires the project to be built with -DENABLE_PKCS11=ON (libp11).
    static Keystore loadPkcs11(const std::string& modulePath,
                               const std::string& pin,
                               const std::string& keyId);

    Keystore() = default;
    Keystore(const Keystore&) = delete;
    Keystore& operator=(const Keystore&) = delete;
    Keystore(Keystore&&) noexcept;
    Keystore& operator=(Keystore&&) noexcept;
    ~Keystore();

    X509* cert() const { return cert_; }
    EVP_PKEY* key() const { return key_; }
    const std::vector<X509*>& chain() const { return chain_; }

private:
    X509* cert_ = nullptr;
    EVP_PKEY* key_ = nullptr;
    std::vector<X509*> chain_;

    // Opaque PKCS#11 context kept alive while a token-backed key is in use.
    void* p11ctx_ = nullptr;
};

} // namespace jsp
