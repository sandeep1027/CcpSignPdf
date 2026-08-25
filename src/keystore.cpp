// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#include "keystore.hpp"

#include <openssl/err.h>
#include <stdexcept>
#include <cstdio>

#ifdef JSP_ENABLE_PKCS11
#include <libp11.h>
#endif

namespace jsp {

namespace {
std::string opensslError(const std::string& ctx) {
    unsigned long e = ERR_get_error();
    char buf[256] = {0};
    if (e) ERR_error_string_n(e, buf, sizeof(buf));
    return ctx + (e ? std::string(": ") + buf : std::string(": unknown error"));
}
} // namespace

Keystore Keystore::loadPkcs12(const std::string& path, const std::string& password) {
    FILE* fp = std::fopen(path.c_str(), "rb");
    if (!fp) throw std::runtime_error("cannot open keystore: " + path);

    PKCS12* p12 = d2i_PKCS12_fp(fp, nullptr);
    std::fclose(fp);
    if (!p12) throw std::runtime_error(opensslError("failed to parse PKCS#12"));

    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    STACK_OF(X509)* ca = nullptr;
    if (!PKCS12_parse(p12, password.c_str(), &pkey, &cert, &ca)) {
        PKCS12_free(p12);
        throw std::runtime_error(opensslError("PKCS#12 parse failed (wrong password?)"));
    }
    PKCS12_free(p12);

    if (!pkey) { if (cert) X509_free(cert); throw std::runtime_error("keystore has no private key"); }
    if (!cert) { EVP_PKEY_free(pkey); throw std::runtime_error("keystore has no certificate"); }

    Keystore ks;
    ks.key_ = pkey;
    ks.cert_ = cert;
    if (ca) {
        for (int i = 0; i < sk_X509_num(ca); ++i) {
            X509* c = sk_X509_value(ca, i);
            X509_up_ref(c);
            ks.chain_.push_back(c);
        }
        sk_X509_pop_free(ca, X509_free);
    }
    return ks;
}

#ifdef JSP_ENABLE_PKCS11
Keystore Keystore::loadPkcs11(const std::string& modulePath,
                              const std::string& pin,
                              const std::string& keyId) {
    PKCS11_CTX* ctx = PKCS11_CTX_new();
    if (!ctx) throw std::runtime_error("PKCS11_CTX_new failed");
    if (PKCS11_CTX_load(ctx, modulePath.c_str()) != 0) {
        PKCS11_CTX_free(ctx);
        throw std::runtime_error("cannot load PKCS#11 module: " + modulePath);
    }

    PKCS11_SLOT* slots = nullptr;
    unsigned int nslots = 0;
    if (PKCS11_enumerate_slots(ctx, &slots, &nslots) != 0) {
        PKCS11_CTX_unload(ctx); PKCS11_CTX_free(ctx);
        throw std::runtime_error("PKCS11_enumerate_slots failed");
    }

    PKCS11_SLOT* slot = PKCS11_find_token(ctx, slots, nslots);
    if (!slot || !slot->token) {
        PKCS11_release_all_slots(ctx, slots, nslots);
        PKCS11_CTX_unload(ctx); PKCS11_CTX_free(ctx);
        throw std::runtime_error("no PKCS#11 token found");
    }

    if (PKCS11_login(slot, 0, pin.c_str()) != 0) {
        PKCS11_release_all_slots(ctx, slots, nslots);
        PKCS11_CTX_unload(ctx); PKCS11_CTX_free(ctx);
        throw std::runtime_error("PKCS#11 login failed (wrong PIN?)");
    }

    // Locate the private key (optionally matching a label/id).
    PKCS11_KEY* keys = nullptr; unsigned int nkeys = 0;
    if (PKCS11_enumerate_keys(slot->token, &keys, &nkeys) != 0 || nkeys == 0) {
        PKCS11_release_all_slots(ctx, slots, nslots);
        PKCS11_CTX_unload(ctx); PKCS11_CTX_free(ctx);
        throw std::runtime_error("no private keys on token");
    }
    PKCS11_KEY* chosen = &keys[0];
    if (!keyId.empty())
        for (unsigned int i = 0; i < nkeys; ++i)
            if (keys[i].label && keyId == keys[i].label) { chosen = &keys[i]; break; }

    EVP_PKEY* pkey = PKCS11_get_private_key(chosen);
    if (!pkey) {
        PKCS11_release_all_slots(ctx, slots, nslots);
        PKCS11_CTX_unload(ctx); PKCS11_CTX_free(ctx);
        throw std::runtime_error("PKCS11_get_private_key failed");
    }

    // Matching certificate.
    PKCS11_CERT* certs = nullptr; unsigned int ncerts = 0;
    X509* cert = nullptr;
    if (PKCS11_enumerate_certs(slot->token, &certs, &ncerts) == 0 && ncerts > 0)
        cert = X509_dup(certs[0].x509);
    if (!cert) {
        EVP_PKEY_free(pkey);
        PKCS11_release_all_slots(ctx, slots, nslots);
        PKCS11_CTX_unload(ctx); PKCS11_CTX_free(ctx);
        throw std::runtime_error("no certificate on token");
    }

    Keystore ks;
    ks.key_ = pkey;      // backed by the token; ctx must stay alive
    ks.cert_ = cert;
    ks.p11ctx_ = ctx;    // keep the module loaded until destruction
    (void)slots; (void)nslots; // released on CTX unload
    return ks;
}
#else
Keystore Keystore::loadPkcs11(const std::string&, const std::string&, const std::string&) {
    throw std::runtime_error("PKCS#11 support not compiled in (rebuild with -DENABLE_PKCS11=ON)");
}
#endif

Keystore::Keystore(Keystore&& o) noexcept
    : cert_(o.cert_), key_(o.key_), chain_(std::move(o.chain_)), p11ctx_(o.p11ctx_) {
    o.cert_ = nullptr; o.key_ = nullptr; o.chain_.clear(); o.p11ctx_ = nullptr;
}

Keystore& Keystore::operator=(Keystore&& o) noexcept {
    if (this != &o) {
        this->~Keystore();
        cert_ = o.cert_; key_ = o.key_; chain_ = std::move(o.chain_); p11ctx_ = o.p11ctx_;
        o.cert_ = nullptr; o.key_ = nullptr; o.chain_.clear(); o.p11ctx_ = nullptr;
    }
    return *this;
}

Keystore::~Keystore() {
    if (cert_) X509_free(cert_);
    if (key_) EVP_PKEY_free(key_);
    for (X509* c : chain_) X509_free(c);
    cert_ = nullptr; key_ = nullptr; chain_.clear();
#ifdef JSP_ENABLE_PKCS11
    if (p11ctx_) {
        PKCS11_CTX* ctx = static_cast<PKCS11_CTX*>(p11ctx_);
        PKCS11_CTX_unload(ctx);
        PKCS11_CTX_free(ctx);
    }
#endif
    p11ctx_ = nullptr;
}

} // namespace jsp
