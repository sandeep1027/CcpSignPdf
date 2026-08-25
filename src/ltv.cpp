// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#include "ltv.hpp"

#include <openssl/ocsp.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <curl/curl.h>
#include <stdexcept>
#include <iostream>

using namespace PoDoFo;

namespace jsp {

namespace {

size_t writeCb(char* ptr, size_t sz, size_t nm, void* ud) {
    auto* out = static_cast<std::vector<unsigned char>*>(ud);
    out->insert(out->end(), ptr, ptr + sz * nm);
    return sz * nm;
}

// Simple HTTP helper. If postBody is non-null, does a POST with contentType.
std::vector<unsigned char> httpFetch(const std::string& url,
                                     const std::vector<unsigned char>* postBody,
                                     const char* contentType) {
    std::vector<unsigned char> out;
    CURL* c = curl_easy_init();
    if (!c) return out;
    struct curl_slist* hdrs = nullptr;
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, writeCb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    if (postBody) {
        std::string ct = std::string("Content-Type: ") + contentType;
        hdrs = curl_slist_append(hdrs, ct.c_str());
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
        curl_easy_setopt(c, CURLOPT_POST, 1L);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, postBody->data());
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)postBody->size());
    }
    CURLcode rc = curl_easy_perform(c);
    long http = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http);
    if (hdrs) curl_slist_free_all(hdrs);
    curl_easy_cleanup(c);
    if (rc != CURLE_OK || (http && http != 200)) out.clear();
    return out;
}

std::vector<unsigned char> derOf(X509* c) {
    int len = i2d_X509(c, nullptr);
    std::vector<unsigned char> v(len > 0 ? len : 0);
    if (len > 0) { unsigned char* p = v.data(); i2d_X509(c, &p); }
    return v;
}

// Fetch one OCSP response for cert signed by issuer.
std::vector<unsigned char> fetchOcsp(X509* cert, X509* issuer) {
    std::vector<unsigned char> result;
    STACK_OF(OPENSSL_STRING)* urls = X509_get1_ocsp(cert);
    if (!urls || sk_OPENSSL_STRING_num(urls) == 0) { if (urls) X509_email_free(urls); return result; }
    std::string url = sk_OPENSSL_STRING_value(urls, 0);
    X509_email_free(urls);

    OCSP_REQUEST* req = OCSP_REQUEST_new();
    OCSP_CERTID* id = OCSP_cert_to_id(nullptr, cert, issuer);
    if (!id) { OCSP_REQUEST_free(req); return result; }
    OCSP_request_add0_id(req, id);

    int len = i2d_OCSP_REQUEST(req, nullptr);
    std::vector<unsigned char> body(len > 0 ? len : 0);
    unsigned char* p = body.data();
    i2d_OCSP_REQUEST(req, &p);
    OCSP_REQUEST_free(req);

    result = httpFetch(url, &body, "application/ocsp-request");
    return result;
}

// Fetch one CRL from the cert's first CRL distribution point (HTTP only).
std::vector<unsigned char> fetchCrl(X509* cert) {
    std::vector<unsigned char> result;
    auto* dps = static_cast<CRL_DIST_POINTS*>(
        X509_get_ext_d2i(cert, NID_crl_distribution_points, nullptr, nullptr));
    if (!dps) return result;
    for (int i = 0; i < sk_DIST_POINT_num(dps) && result.empty(); ++i) {
        DIST_POINT* dp = sk_DIST_POINT_value(dps, i);
        if (!dp->distpoint || dp->distpoint->type != 0) continue;
        GENERAL_NAMES* names = dp->distpoint->name.fullname;
        for (int j = 0; j < sk_GENERAL_NAME_num(names); ++j) {
            GENERAL_NAME* gn = sk_GENERAL_NAME_value(names, j);
            if (gn->type != GEN_URI) continue;
            std::string url((char*)ASN1_STRING_get0_data(gn->d.uniformResourceIdentifier),
                            ASN1_STRING_length(gn->d.uniformResourceIdentifier));
            if (url.rfind("http", 0) != 0) continue;
            result = httpFetch(url, nullptr, nullptr);
            if (!result.empty()) break;
        }
    }
    CRL_DIST_POINTS_free(dps);
    return result;
}

} // namespace

ValidationInfo collectValidationInfo(const Keystore& ks, bool useOcsp, bool useCrl) {
    ValidationInfo info;
    if (!ks.cert()) return info;

    // Build the ordered list: signer cert followed by chain certs.
    std::vector<X509*> chain;
    chain.push_back(ks.cert());
    for (X509* c : ks.chain()) chain.push_back(c);

    for (X509* c : chain) info.certs.push_back(derOf(c));

    // For each cert, its issuer is the next one in the chain (best effort).
    for (size_t i = 0; i < chain.size(); ++i) {
        X509* cert = chain[i];
        X509* issuer = (i + 1 < chain.size()) ? chain[i + 1] : chain[i];
        if (useOcsp) {
            auto resp = fetchOcsp(cert, issuer);
            if (!resp.empty()) info.ocspResponses.push_back(std::move(resp));
        }
        if (useCrl) {
            auto crl = fetchCrl(cert);
            if (!crl.empty()) info.crls.push_back(std::move(crl));
        }
    }
    return info;
}

void embedDss(PdfMemDocument& doc, const ValidationInfo& info) {
    if (info.empty()) return;

    auto& objects = doc.GetObjects();

    // Helper: create an indirect stream object from raw bytes, return a ref.
    auto makeStream = [&](const std::vector<unsigned char>& data) -> PdfReference {
        PdfObject& obj = objects.CreateDictionaryObject();
        obj.GetOrCreateStream().SetData(
            bufferview(reinterpret_cast<const char*>(data.data()), data.size()));
        return obj.GetIndirectReference();
    };

    auto buildArray = [&](const std::vector<std::vector<unsigned char>>& items) {
        PdfArray arr;
        for (const auto& it : items) arr.Add(makeStream(it));
        return arr;
    };

    PdfObject& dss = objects.CreateDictionaryObject();
    PdfDictionary& d = dss.GetDictionary();
    if (!info.certs.empty())         d.AddKey("Certs", buildArray(info.certs));
    if (!info.ocspResponses.empty()) d.AddKey("OCSPs", buildArray(info.ocspResponses));
    if (!info.crls.empty())          d.AddKey("CRLs",  buildArray(info.crls));

    // Attach /DSS to the document catalog.
    doc.GetCatalog().GetDictionary().AddKey("DSS", dss.GetIndirectReference());
}

} // namespace jsp
