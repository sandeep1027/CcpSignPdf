// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#include "cms.hpp"
#include "crypto_util.hpp"

#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/provider.h>
#include <stdexcept>
#include <memory>

namespace jsp {

namespace {

// OpenSSL 3 gates legacy algorithms (RIPEMD160 etc.) behind the "legacy"
// provider; load it best-effort so --hash RIPEMD160 works where available.
struct LegacyProviderLoader {
    OSSL_PROVIDER* prov = nullptr;
    LegacyProviderLoader() { prov = OSSL_PROVIDER_load(nullptr, "legacy"); }
    ~LegacyProviderLoader() { if (prov) OSSL_PROVIDER_unload(prov); }
};

std::string sslErr(const std::string& ctx) {
    unsigned long e = ERR_get_error();
    char buf[256] = {0};
    if (e) ERR_error_string_n(e, buf, sizeof(buf));
    return ctx + (e ? std::string(": ") + buf : "");
}

// Attach an RFC 3161 timestamp token to a signer's unsigned attributes.
// The message imprint is a digest of the signer's signature value.
void attachTimestamp(PKCS7_SIGNER_INFO* si, const TsaParams& tsa) {
    ASN1_OCTET_STRING* sig = si->enc_digest;
    std::vector<unsigned char> sigVal(sig->data, sig->data + sig->length);

    std::vector<unsigned char> token = requestTimestampToken(tsa, sigVal);

    const unsigned char* tp = token.data();
    ASN1_TYPE* t = d2i_ASN1_TYPE(nullptr, &tp, (long)token.size());
    if (!t || t->type != V_ASN1_SEQUENCE) {
        if (t) ASN1_TYPE_free(t);
        throw std::runtime_error("malformed timestamp token");
    }

    ASN1_OBJECT* obj = OBJ_txt2obj("1.2.840.113549.1.9.16.2.14", 1);
    X509_ATTRIBUTE* attr = X509_ATTRIBUTE_new();
    X509_ATTRIBUTE_set1_object(attr, obj);
    X509_ATTRIBUTE_set1_data(attr, V_ASN1_SEQUENCE,
                             t->value.sequence->data, t->value.sequence->length);
    ASN1_OBJECT_free(obj);
    ASN1_TYPE_free(t);

    if (!si->unauth_attr) si->unauth_attr = sk_X509_ATTRIBUTE_new_null();
    sk_X509_ATTRIBUTE_push(si->unauth_attr, attr);
}

} // namespace

std::vector<unsigned char> buildDetachedCms(
    const Keystore& ks,
    const std::vector<unsigned char>& content,
    HashAlgo hashAlgo,
    const TsaParams& tsa) {

    if (!ks.cert() || !ks.key())
        throw std::runtime_error("keystore not initialised");

    LegacyProviderLoader legacy;

    STACK_OF(X509)* certs = sk_X509_new_null();
    for (X509* c : ks.chain()) sk_X509_push(certs, c);

    int flags = PKCS7_DETACHED | PKCS7_BINARY | PKCS7_PARTIAL;
    PKCS7* p7 = PKCS7_sign(nullptr, nullptr, certs, nullptr, flags);
    sk_X509_free(certs);
    if (!p7) throw std::runtime_error(sslErr("PKCS7_sign init failed"));
    std::unique_ptr<PKCS7, decltype(&PKCS7_free)> guard(p7, PKCS7_free);

    PKCS7_SIGNER_INFO* si = PKCS7_sign_add_signer(
        p7, ks.cert(), ks.key(), evpMd(hashAlgo), 0);
    if (!si) throw std::runtime_error(sslErr("PKCS7_sign_add_signer failed"));

    BIO* data = BIO_new_mem_buf(content.data(), (int)content.size());
    if (!data) throw std::runtime_error("BIO_new_mem_buf failed");
    std::unique_ptr<BIO, decltype(&BIO_free)> dguard(data, BIO_free);

    if (!PKCS7_final(p7, data, PKCS7_DETACHED | PKCS7_BINARY))
        throw std::runtime_error(sslErr("PKCS7_final failed"));

    if (!tsa.url.empty())
        attachTimestamp(si, tsa);

    int len = i2d_PKCS7(p7, nullptr);
    if (len <= 0) throw std::runtime_error(sslErr("i2d_PKCS7 failed"));
    std::vector<unsigned char> out(static_cast<size_t>(len));
    unsigned char* p = out.data();
    i2d_PKCS7(p7, &p);
    return out;
}

} // namespace jsp
