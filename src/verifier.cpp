// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#include "verifier.hpp"

#include <podofo/podofo.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <fstream>
#include <stdexcept>
#include <memory>

using namespace PoDoFo;

namespace jsp {

namespace {

std::vector<unsigned char> readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open PDF: " + path);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(f)),
                                      std::istreambuf_iterator<char>());
}

// Load PEM CA certificates from a directory into an X509_STORE.
X509_STORE* buildStore(const std::string& dir) {
    X509_STORE* store = X509_STORE_new();
    if (!dir.empty())
        X509_STORE_load_locations(store, nullptr, dir.c_str());
    return store;
}

std::string signerSubject(PKCS7* p7) {
    STACK_OF(X509)* certs = nullptr;
    if (PKCS7_type_is_signed(p7)) certs = p7->d.sign->cert;
    if (certs && sk_X509_num(certs) > 0) {
        X509* c = sk_X509_value(certs, 0);
        char buf[256] = {0};
        X509_NAME_oneline(X509_get_subject_name(c), buf, sizeof(buf));
        return buf;
    }
    return "(unknown)";
}

bool hasTimestampAttr(PKCS7* p7) {
    if (!PKCS7_type_is_signed(p7)) return false;
    STACK_OF(PKCS7_SIGNER_INFO)* sis = PKCS7_get_signer_info(p7);
    if (!sis) return false;
    for (int i = 0; i < sk_PKCS7_SIGNER_INFO_num(sis); ++i) {
        PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(sis, i);
        if (!si->unauth_attr) continue;
        for (int j = 0; j < sk_X509_ATTRIBUTE_num(si->unauth_attr); ++j) {
            X509_ATTRIBUTE* a = sk_X509_ATTRIBUTE_value(si->unauth_attr, j);
            char oid[128] = {0};
            OBJ_obj2txt(oid, sizeof(oid), X509_ATTRIBUTE_get0_object(a), 1);
            if (std::string(oid) == "1.2.840.113549.1.9.16.2.14") return true;
        }
    }
    return false;
}

// Total length of the DER SEQUENCE at d, or 0 when malformed. Signature
// /Contents placeholders are zero-padded to a fixed reserve, so callers must
// trim to this length before handing the blob to OpenSSL.
size_t derSequenceLength(const unsigned char* d, size_t avail) {
    if (avail < 2 || d[0] != 0x30) return 0;
    if ((d[1] & 0x80) == 0) return 2u + d[1];
    int n = d[1] & 0x7F;
    if (n == 0 || n > 4 || (size_t)(2 + n) > avail) return 0;
    size_t len = 0;
    for (int i = 0; i < n; ++i)
        len = (len << 8) | d[2 + i];
    return 2u + (size_t)n + len;
}

} // namespace

std::vector<SignatureReport> verifyPdf(const VerifyOptions& opt) {
    std::vector<unsigned char> raw = readFile(opt.inputPath);
    std::vector<SignatureReport> reports;

    PdfMemDocument doc;
    doc.Load(opt.inputPath);
    PdfAcroForm* acro = doc.GetAcroForm();
    if (!acro) return reports; // no fields => no signatures

    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>
        store(buildStore(opt.trustedCertsDir), X509_STORE_free);
    int vflags = opt.trustedCertsDir.empty() ? PKCS7_NOVERIFY : 0;

    unsigned count = acro->GetFieldCount();
    for (unsigned i = 0; i < count; ++i) {
        PdfField& field = acro->GetFieldAt(i);
        auto* sig = dynamic_cast<PdfSignature*>(&field);
        if (!sig) continue;

        SignatureReport r;
        auto name = field.GetName();
        r.fieldName = name.has_value() ? name->GetString() : std::string("(unnamed)");

        // The signature value dictionary (with /Contents and /ByteRange) is the
        // field's /V entry. This PoDoFo build has no PdfSignature::GetSignatureObject(),
        // so reach it through the field object.
        const PdfObject& fieldObj = sig->GetObject();
        const PdfObject* sigObj = fieldObj.GetDictionary().FindKey("V");
        if (sigObj == nullptr) sigObj = &fieldObj;  // fallback: field IS the value dict
        if (!sigObj->IsDictionary()) {
            r.detail = "no signature dictionary"; reports.push_back(r); continue;
        }
        const PdfDictionary& d = sigObj->GetDictionary();

        const PdfObject* contents = d.FindKey("Contents");
        const PdfObject* byteRange = d.FindKey("ByteRange");
        if (!contents || !byteRange || !byteRange->IsArray()) {
            r.detail = "missing Contents/ByteRange"; reports.push_back(r); continue;
        }

        // Reconstruct the signed byte ranges from the raw file.
        const PdfArray& br = byteRange->GetArray();
        if (br.GetSize() < 4) {
            r.detail = "malformed ByteRange"; reports.push_back(r); continue;
        }
        int64_t a0 = br[0].GetNumber(), a1 = br[1].GetNumber();
        int64_t b0 = br[2].GetNumber(), b1 = br[3].GetNumber();
        std::vector<unsigned char> signedBytes;
        signedBytes.insert(signedBytes.end(), raw.begin() + a0, raw.begin() + a0 + a1);
        signedBytes.insert(signedBytes.end(), raw.begin() + b0, raw.begin() + b0 + b1);
        r.coversWholeFile = (b0 + b1 >= (int64_t)raw.size() - 2);

        // Parse the embedded PKCS#7/CMS blob, trimmed of zero padding.
        // NOTE: GetRawData() returns the unconverted bytes; GetString()
        // would re-encode the binary blob as UTF-8 and corrupt it.
        const std::string& cmsRaw = contents->GetString().GetRawData();
        const unsigned char* q = reinterpret_cast<const unsigned char*>(cmsRaw.data());
        size_t derLen = derSequenceLength(q, cmsRaw.size());
        if (derLen == 0 || derLen > cmsRaw.size()) {
            r.detail = "cannot parse CMS"; reports.push_back(r); continue;
        }
        const unsigned char* p = q;
        PKCS7* p7 = d2i_PKCS7(nullptr, &p, (long)derLen);
        if (!p7) { r.detail = "cannot parse CMS"; reports.push_back(r); continue; }
        std::unique_ptr<PKCS7, decltype(&PKCS7_free)> pguard(p7, PKCS7_free);

        BIO* content = BIO_new_mem_buf(signedBytes.data(), (int)signedBytes.size());
        int ok = PKCS7_verify(p7, nullptr, store.get(), content, nullptr, vflags);
        BIO_free(content);

        r.integrityValid = (ok == 1);
        r.signerSubject = signerSubject(p7);
        r.hasTimestamp = hasTimestampAttr(p7);
        if (!r.integrityValid) {
            char e[256] = {0};
            ERR_error_string_n(ERR_get_error(), e, sizeof(e));
            r.detail = std::string("verify failed: ") + e;
        } else {
            r.detail = "OK";
        }
        reports.push_back(r);
    }
    return reports;
}

} // namespace jsp
