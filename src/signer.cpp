// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#include "signer.hpp"
#include "keystore.hpp"
#include "cms.hpp"
#include "ltv.hpp"

#include <podofo/podofo.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <stdexcept>
#include <vector>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <filesystem>

using namespace PoDoFo;

namespace jsp {

namespace {

// Reserved /Contents placeholder. Must exceed the largest expected CMS blob
// (signature + full chain + timestamp token). 64 KiB is generous.
constexpr size_t kReservedSignatureSize = 64 * 1024;

// PoDoFo signer delegating CMS construction to our OpenSSL builder, so we can
// choose the hash algorithm and embed an RFC 3161 timestamp.
class ExternalCmsSigner : public PdfSigner {
public:
    ExternalCmsSigner(Keystore ks, HashAlgo hash, TsaParams tsa)
        : m_ks(std::move(ks)), m_hash(hash), m_tsa(std::move(tsa)) {}

    void Reset() override { m_buffer.clear(); }

    void AppendData(const bufferview& data) override {
        m_buffer.insert(m_buffer.end(), data.data(), data.data() + data.size());
    }

    void ComputeSignature(charbuff& contents, bool dryrun) override {
        if (dryrun) {
            contents.resize(kReservedSignatureSize);
            std::memset(contents.data(), 0, contents.size());
            return;
        }
        std::vector<unsigned char> cms =
            buildDetachedCms(m_ks, m_buffer, m_hash, m_tsa);
        if (cms.size() > kReservedSignatureSize)
            throw std::runtime_error("signature exceeds reserved size; increase kReservedSignatureSize");
        contents.assign(reinterpret_cast<const char*>(cms.data()), cms.size());
    }

    std::string GetSignatureFilter() const override { return "Adobe.PPKLite"; }
    std::string GetSignatureSubFilter() const override { return "adbe.pkcs7.detached"; }
    std::string GetSignatureType() const override { return "Sig"; }

private:
    Keystore m_ks;
    HashAlgo m_hash;
    TsaParams m_tsa;
    std::vector<unsigned char> m_buffer;
};

// Derive the effective output path from explicit --out, or from
// dir/prefix/suffix like JSignPdf (-d/-op/-os).
std::string resolveOutputPath(const SignOptions& o) {
    if (!o.outputPath.empty()) return o.outputPath;
    std::filesystem::path in(o.inputPath);
    std::string stem = in.stem().string();
    std::string ext = in.extension().string();
    std::string name = o.outPrefix + stem + o.outSuffix + ext;
    std::filesystem::path dir = o.outDir.empty() ? in.parent_path()
                                                 : std::filesystem::path(o.outDir);
    return (dir / name).string();
}

// Format an ASN.1 certificate time as "YYYY-MM-DD HH:MM:SS UTC".
std::string formatAsn1Time(const ASN1_TIME* t) {
    if (!t) return "(unknown)";
    struct tm tmv = {};
    ASN1_TIME_to_tm(t, &tmv);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d UTC",
                  tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                  tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return buf;
}

// Expand template variables in signature text layers:
//   ${signer}    signer name (--name or the cert CN)
//   ${subject}   full X.509 subject DN of the signing certificate
//   ${notAfter}  certificate expiry ("Valid Until")
//   ${timestamp} signing date & time
std::string expandTemplate(const std::string& in, const SignOptions& o,
                           const Keystore& ks) {
    auto cn = [&ks]() -> std::string {
        if (ks.cert()) {
            char buf[512] = {0};
            X509_NAME* n = X509_get_subject_name(ks.cert());
            int idx = X509_NAME_get_index_by_NID(n, NID_commonName, -1);
            if (idx >= 0) {
                ASN1_STRING* s = X509_NAME_ENTRY_get_data(
                    X509_NAME_get_entry(n, idx));
                return std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(s)),
                                   ASN1_STRING_length(s));
            }
            X509_NAME_oneline(n, buf, sizeof(buf));
            return buf;
        }
        return "(unknown)";
    };

    std::string out = in;
    const std::pair<const char*, std::string> vars[] = {
        {"${signer}",    o.signerName.empty() ? cn() : o.signerName},
        {"${subject}",   [&]() {
            if (!ks.cert()) return std::string("(unknown)");
            char buf[512] = {0};
            X509_NAME_oneline(X509_get_subject_name(ks.cert()),
                              buf, sizeof(buf));
            return std::string(buf);
        }()},
        {"${notAfter}",  formatAsn1Time(X509_get0_notAfter(ks.cert()))},
        {"${timestamp}", formatAsn1Time(
            X509_gmtime_adj(nullptr, 0))},
    };
    for (const auto& [key, val] : vars) {
        size_t pos = 0;
        while ((pos = out.find(key, pos)) != std::string::npos) {
            out.replace(pos, std::strlen(key), val);
            pos += val.size();
        }
    }
    return out;
}

// Build the layer-2 text shown in a visible signature, honoring -l2t override.
std::string buildL2Text(const SignOptions& o, const Keystore& ks) {
    if (!o.visible.l2Text.empty())
        return expandTemplate(o.visible.l2Text, o, ks);
    std::string t = "Digitally signed";
    if (!o.signerName.empty())  t += " by " + o.signerName;
    if (!o.reason.empty())      t += "\nReason: " + o.reason;
    if (!o.location.empty())    t += "\nLocation: " + o.location;
    if (!o.contactInfo.empty()) t += "\nContact: " + o.contactInfo;
    return t;
}

// Build the visible signature appearance as a reusable XObject form. The
// (potentially expensive) drawing + image decode happens exactly ONCE here;
// the returned form can be shared by the signature widget and by stamp
// annotations on every other page, which is what makes --all-pages fast.
std::unique_ptr<PdfXObjectForm> buildVisibleAppearance(PdfMemDocument& doc,
                                                       const SignOptions& o,
                                                       const Keystore& ks) {
    const VisibleSignature& v = o.visible;
    double w = v.urx - v.llx, h = v.ury - v.lly;
    if (w <= 0 || h <= 0) return nullptr;

    auto xobj = doc.CreateXObjectForm(Rect(0, 0, w, h));
    PdfPainter painter;
    painter.SetCanvas(*xobj);

    double textX = 4.0;

    // Background image: stretched across the FULL box and drawn first, so
    // every later operator (border, text) paints on top of it. Draw order is
    // z-order in PDF content streams.
    if (!v.bgImagePath.empty()) {
        try {
            auto img = doc.CreateImage();
            img->Load(v.bgImagePath);
            painter.DrawImage(*img, 0, 0,
                              w / img->GetWidth(), h / img->GetHeight());
        } catch (...) { /* image is best-effort */ }
    }

    // Prefer the built-in standard-14 Helvetica (no system fonts needed);
    // SearchFont depends on fontconfig and may fail on minimal systems.
    PdfFont* font = nullptr;
    try {
        font = &doc.GetFonts().GetStandard14Font(PdfStandard14FontType::Helvetica);
    } catch (...) {
        font = doc.GetFonts().SearchFont("Helvetica");
    }
    double fs = v.fontSize > 0 ? v.fontSize : 8.0;
    if (font) painter.TextState.SetFont(*font, fs);

    painter.GraphicsState.SetLineWidth(0.75);
    // DrawRectangle paints the path itself (mode defaults to PdfPathDrawMode::Stroke);
    // the low-level stroke()/fill() operators are private in PoDoFo 0.10.
    painter.DrawRectangle(1, 1, w - 2, h - 2);

    if (font) {
        double y = h - fs - 2;
        std::string text = (v.renderMode == RenderMode::SignerNameAndDescription
                            && !o.signerName.empty())
                           ? (expandTemplate(o.signerName, o, ks) + "\n" + buildL2Text(o, ks))
                           : buildL2Text(o, ks);
        // Split on newlines and draw each line.
        size_t start = 0;
        while (start <= text.size()) {
            size_t nl = text.find('\n', start);
            std::string line = text.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
            painter.DrawText(line, textX, y);
            y -= (fs + 2);
            if (nl == std::string::npos) break;
            start = nl + 1;
        }
        // Layer-4 custom footer text, drawn along the bottom edge.
        if (!v.l4Text.empty())
            painter.DrawText(expandTemplate(v.l4Text, o, ks), textX, 4);
    }

    painter.FinishDrawing();
    return xobj;
}

// Place the shared appearance on every page except the one that carries the
// real signature widget (which is set separately). These are visual-only
// /Stamp annotations that reference the SAME XObject, so there is no per-page
// redraw or image re-decode — the cost is one lightweight annotation per page.
void stampAllPages(PdfMemDocument& doc, PdfXObjectForm& xobj,
                   const SignOptions& o, unsigned signaturePageIndex) {
    double w = o.visible.urx - o.visible.llx;
    double h = o.visible.ury - o.visible.lly;
    Rect rect(o.visible.llx, o.visible.lly, w, h);

    unsigned count = doc.GetPages().GetCount();
    for (unsigned p = 0; p < count; ++p) {
        if (p == signaturePageIndex) continue;
        PdfPage& pg = doc.GetPages().GetPageAt(p);
        auto& annot = pg.GetAnnotations().CreateAnnot<PdfAnnotationStamp>(rect);
        annot.SetAppearanceStream(xobj);
        annot.SetFlags(PdfAnnotationFlags::Print);
    }
}

// Apply a DocMDP certification level via /Perms. EXPERIMENTAL: builds the
// transform dictionaries manually since PoDoFo lacks a direct helper.
void applyCertification(PdfMemDocument& doc, PdfSignature& sig, CertLevel level) {
    if (level == CertLevel::NotCertified) return;
    auto& objects = doc.GetObjects();

    PdfObject& tp = objects.CreateDictionaryObject();
    tp.GetDictionary().AddKey(PdfName("Type"), PdfName("TransformParams"));
    tp.GetDictionary().AddKey(PdfName("V"), PdfName("1.2"));
    tp.GetDictionary().AddKey(PdfName("P"), PdfObject(static_cast<int64_t>(level)));

    PdfObject& ref = objects.CreateDictionaryObject();
    ref.GetDictionary().AddKey(PdfName("Type"), PdfName("SigRef"));
    ref.GetDictionary().AddKey(PdfName("TransformMethod"), PdfName("DocMDP"));
    ref.GetDictionary().AddKey(PdfName("TransformParams"), tp.GetIndirectReference());

    PdfArray refs;
    refs.Add(ref.GetIndirectReference());
    sig.GetObject().GetDictionary().AddKey(PdfName("Reference"), refs);

    // /Perms -> /DocMDP points at the signature.
    PdfObject& perms = objects.CreateDictionaryObject();
    perms.GetDictionary().AddKey(PdfName("DocMDP"), sig.GetObject().GetIndirectReference());
    doc.GetCatalog().GetDictionary().AddKey(PdfName("Perms"), perms.GetIndirectReference());
}

// Apply output encryption. EXPERIMENTAL: combining encryption with signing is
// not supported by every PoDoFo build; if it fails, sign first then encrypt in
// a separate pass.
void applyEncryption(PdfMemDocument& doc, const SignOptions& o) {
    if (o.encryption == EncryptionMode::None) return;

    PdfPermissions perms = PdfPermissions::None;
    if (o.permPrinting) perms |= PdfPermissions::Print;
    if (o.permModify)   perms |= PdfPermissions::Edit;
    if (o.permCopy)     perms |= PdfPermissions::Copy;
    if (o.permAnnotate) perms |= PdfPermissions::EditNotes;

    // Use SetEncrypted's default cipher/key length. The AES-256 enum names
    // (PdfEncryptionAlgorithm/PdfKeyLength::L256) vary across 0.10.x point
    // releases, so we rely on PoDoFo's built-in default here for portability.
    doc.SetEncrypted(o.userPassword, o.ownerPassword, perms);
}

} // namespace

std::string signPdf(const SignOptions& opt) {
    Keystore ks = (opt.keystoreType == KeystoreType::PKCS11)
        ? Keystore::loadPkcs11(opt.keystorePath, opt.keystorePass, opt.keyAlias)
        : Keystore::loadPkcs12(opt.keystorePath, opt.keystorePass);

    // PoDoFo's SignDocument() appends an incremental update whose /Prev must
    // point at the xref of the file being signed, so materialize the base
    // document at the final location first and load it back from there.
    std::string outPath = resolveOutputPath(opt);
    if (outPath != opt.inputPath) {
        std::error_code ec;
        std::filesystem::copy_file(opt.inputPath, outPath,
                                   std::filesystem::copy_options::overwrite_existing,
                                   ec);
        if (ec)
            throw std::runtime_error("cannot create output file '" + outPath +
                                     "': " + ec.message());
    }

    PdfMemDocument doc;
    doc.Load(outPath);
    doc.GetOrCreateAcroForm();

    // Long-term validation material must be embedded before signing so that it
    // is covered by the signature's ByteRange.
    if (opt.ocsp || opt.crl) {
        ValidationInfo vi = collectValidationInfo(ks, opt.ocsp, opt.crl);
        embedDss(doc, vi);
    }

    if (opt.encryption != EncryptionMode::None)
        applyEncryption(doc, opt);

    unsigned pageIndex = opt.visible.enabled
        ? static_cast<unsigned>(opt.visible.page - 1) : 0u;
    if (pageIndex >= doc.GetPages().GetCount())
        throw std::runtime_error("page index out of range");

    PdfPage& page = doc.GetPages().GetPageAt(pageIndex);

    Rect rect = opt.visible.enabled
        ? Rect(opt.visible.llx, opt.visible.lly,
               opt.visible.urx - opt.visible.llx,
               opt.visible.ury - opt.visible.lly)
        : Rect(0, 0, 0, 0);

    // Field names must be unique across revisions when appending multiple
    // signatures (e.g. one per page): count existing /Sig fields.
    std::string fieldName = "Signature1";
    {
        unsigned maxIdx = 0;
        if (auto* acro = doc.GetAcroForm()) {
            unsigned fc = acro->GetFieldCount();
            for (unsigned i = 0; i < fc; ++i) {
                auto n = acro->GetFieldAt(i).GetName();
                if (!n.has_value()) continue;
                std::string nm = n->GetString();
                if (nm.rfind("Signature", 0) == 0) {
                    try { maxIdx = std::max(maxIdx,
                        static_cast<unsigned>(std::stoul(nm.substr(9)))); }
                    catch (...) {}
                }
            }
        }
        if (maxIdx > 0) fieldName = "Signature" + std::to_string(maxIdx + 1);
    }

    PdfSignature& sig = page.CreateField<PdfSignature>(fieldName, rect);
    // The /V value dictionary must exist before setting signature metadata
    sig.EnsureValueObject();
    if (!opt.reason.empty())     sig.SetSignatureReason(PdfString(opt.reason));
    if (!opt.location.empty())   sig.SetSignatureLocation(PdfString(opt.location));
    if (!opt.signerName.empty()) sig.SetSignerName(PdfString(opt.signerName));
    sig.SetSignatureDate(PdfDate::LocalNow());

    applyCertification(doc, sig, opt.certLevel);

    if (opt.visible.enabled) {
        // Draw the appearance once; reuse it for the signature widget and,
        // when --all-pages is set, for a stamp annotation on every other page.
        auto xobj = buildVisibleAppearance(doc, opt, ks);
        if (xobj) {
            auto& widget = sig.MustGetWidget();
            // Make sure readers actually render the appearance
            widget.SetFlags(PdfAnnotationFlags::Print);
            widget.SetAppearanceStream(*xobj);
            if (opt.visible.allPages)
                stampAllPages(doc, *xobj, opt, pageIndex);
        }
    }

    TsaParams tsa;
    tsa.url = opt.tsaUrl; tsa.user = opt.tsaUser; tsa.pass = opt.tsaPass;
    tsa.policyOid = opt.tsaPolicyOid; tsa.hashAlgo = opt.tsaHashAlgo;

    ExternalCmsSigner signer(std::move(ks), opt.hashAlgo, std::move(tsa));

    // Append the signature revision to the base document already on disk.
    // SignDocument() reads the file back to hash it, so read+write access.
    FileStreamDevice out(outPath, FileMode::Open, DeviceAccess::ReadWrite);
    PoDoFo::SignDocument(doc, out, signer, sig);
    return outPath;
}

} // namespace jsp

