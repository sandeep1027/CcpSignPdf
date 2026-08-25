// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#include "timestamp.hpp"
#include "crypto_util.hpp"

#include <openssl/ts.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <curl/curl.h>
#include <stdexcept>
#include <memory>

namespace jsp {

namespace {

std::string sslErr(const std::string& ctx) {
    unsigned long e = ERR_get_error();
    char buf[256] = {0};
    if (e) ERR_error_string_n(e, buf, sizeof(buf));
    return ctx + (e ? std::string(": ") + buf : "");
}

size_t writeCb(char* ptr, size_t sz, size_t nm, void* ud) {
    auto* out = static_cast<std::vector<unsigned char>*>(ud);
    out->insert(out->end(), ptr, ptr + sz * nm);
    return sz * nm;
}

int mdNid(HashAlgo a) {
    switch (a) {
        case HashAlgo::SHA1:      return NID_sha1;
        case HashAlgo::SHA256:    return NID_sha256;
        case HashAlgo::SHA384:    return NID_sha384;
        case HashAlgo::SHA512:    return NID_sha512;
        case HashAlgo::RIPEMD160: return NID_ripemd160;
    }
    return NID_sha256;
}

std::vector<unsigned char> buildTsRequest(const std::vector<unsigned char>& imprint,
                                          HashAlgo algo, const std::string& policyOid) {
    TS_REQ* req = TS_REQ_new();
    if (!req) throw std::runtime_error("TS_REQ_new failed");
    std::unique_ptr<TS_REQ, decltype(&TS_REQ_free)> guard(req, TS_REQ_free);

    TS_REQ_set_version(req, 1);

    TS_MSG_IMPRINT* imp = TS_MSG_IMPRINT_new();
    X509_ALGOR* alg = X509_ALGOR_new();
    alg->algorithm = OBJ_nid2obj(mdNid(algo));
    alg->parameter = ASN1_TYPE_new();
    alg->parameter->type = V_ASN1_NULL;
    TS_MSG_IMPRINT_set_algo(imp, alg);
    TS_MSG_IMPRINT_set_msg(imp, const_cast<unsigned char*>(imprint.data()),
                           static_cast<int>(imprint.size()));
    TS_REQ_set_msg_imprint(req, imp);
    X509_ALGOR_free(alg);
    TS_MSG_IMPRINT_free(imp);

    if (!policyOid.empty()) {
        ASN1_OBJECT* pol = OBJ_txt2obj(policyOid.c_str(), 1);
        if (pol) { TS_REQ_set_policy_id(req, pol); ASN1_OBJECT_free(pol); }
    }

    ASN1_INTEGER* nonce = ASN1_INTEGER_new();
    unsigned char nb[8];
    RAND_bytes(nb, sizeof(nb));
    BIGNUM* bn = BN_bin2bn(nb, sizeof(nb), nullptr);
    BN_to_ASN1_INTEGER(bn, nonce);
    BN_free(bn);
    TS_REQ_set_nonce(req, nonce);
    ASN1_INTEGER_free(nonce);

    TS_REQ_set_cert_req(req, 1);

    int len = i2d_TS_REQ(req, nullptr);
    if (len <= 0) throw std::runtime_error(sslErr("i2d_TS_REQ failed"));
    std::vector<unsigned char> der(static_cast<size_t>(len));
    unsigned char* p = der.data();
    i2d_TS_REQ(req, &p);
    return der;
}

} // namespace

std::vector<unsigned char> requestTimestampToken(
    const TsaParams& params,
    const std::vector<unsigned char>& contentToHash) {

    // Compute the message imprint digest with the requested algorithm.
    const EVP_MD* md = evpMd(params.hashAlgo);
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_Digest(contentToHash.data(), contentToHash.size(), digest, &dlen, md, nullptr);
    std::vector<unsigned char> imprint(digest, digest + dlen);

    std::vector<unsigned char> reqDer =
        buildTsRequest(imprint, params.hashAlgo, params.policyOid);

    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> cguard(curl, curl_easy_cleanup);

    std::vector<unsigned char> respBuf;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/timestamp-query");
    headers = curl_slist_append(headers, "Accept: application/timestamp-reply");

    curl_easy_setopt(curl, CURLOPT_URL, params.url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, reqDer.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)reqDer.size());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &respBuf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    if (!params.user.empty()) {
        curl_easy_setopt(curl, CURLOPT_USERNAME, params.user.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, params.pass.c_str());
    }

    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    if (rc != CURLE_OK)
        throw std::runtime_error(std::string("TSA request failed: ") + curl_easy_strerror(rc));

    long http = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
    if (http != 200)
        throw std::runtime_error("TSA returned HTTP " + std::to_string(http));

    const unsigned char* rp = respBuf.data();
    TS_RESP* resp = d2i_TS_RESP(nullptr, &rp, (long)respBuf.size());
    if (!resp) throw std::runtime_error(sslErr("failed to parse TS_RESP"));
    std::unique_ptr<TS_RESP, decltype(&TS_RESP_free)> rguard(resp, TS_RESP_free);

    TS_STATUS_INFO* si = TS_RESP_get_status_info(resp);
    long status = ASN1_INTEGER_get(TS_STATUS_INFO_get0_status(si));
    if (status != 0 && status != 1)
        throw std::runtime_error("TSA rejected request (status " + std::to_string(status) + ")");

    PKCS7* token = TS_RESP_get_token(resp);
    if (!token) throw std::runtime_error("TSA response has no token");

    int len = i2d_PKCS7(token, nullptr);
    if (len <= 0) throw std::runtime_error(sslErr("i2d_PKCS7 failed"));
    std::vector<unsigned char> out(static_cast<size_t>(len));
    unsigned char* op = out.data();
    i2d_PKCS7(token, &op);
    return out;
}

} // namespace jsp
