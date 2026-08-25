// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace jsp {

enum class HashAlgo { SHA1, SHA256, SHA384, SHA512, RIPEMD160 };

// PDF DocMDP certification level (JSignPdf -cl).
enum class CertLevel {
    NotCertified = 0,
    NoChanges = 1,
    FormFilling = 2,
    FormFillingAndAnnotations = 3
};

// Visible signature layer-2 render mode (JSignPdf -rh).
enum class RenderMode {
    DescriptionOnly,
    GraphicAndDescription,
    SignerNameAndDescription
};

enum class KeystoreType { PKCS12, PKCS11 };

// Output PDF encryption (JSignPdf -ep / passwords / permissions).
enum class EncryptionMode { None, Password, Certificate };

struct VisibleSignature {
    bool enabled = false;
    int page = 1;
    double llx = 36.0, lly = 36.0, urx = 236.0, ury = 108.0;
    RenderMode renderMode = RenderMode::DescriptionOnly;
    std::string l2Text;        // custom layer-2 text; empty = auto
    std::string l4Text;        // custom layer-4 (status) text
    double fontSize = 8.0;     // 0 = auto-fit
    std::string bgImagePath;   // background/graphic image
    double bgScale = -1.0;     // <0 = fit
    bool acro6Layers = true;   // -n disables the n2/n4 layers
    bool allPages = false;     // stamp the visible appearance on every page
};

struct SignOptions {
    // Input / output
    std::string inputPath;
    std::string outputPath;    // explicit output; else derived from dir/prefix/suffix
    std::string outDir;
    std::string outPrefix;
    std::string outSuffix = "_signed";
    bool append = false;       // add a new signature to an already-signed PDF

    // Keystore
    KeystoreType keystoreType = KeystoreType::PKCS12;
    std::string keystorePath;  // .p12 file, or PKCS#11 module .so/.dll
    std::string keystorePass;  // keystore password / PKCS#11 PIN
    std::string keyAlias;      // key alias / PKCS#11 object label or id
    std::string keyPass;       // separate key password (if any)

    // Signature metadata
    std::string reason, location, contactInfo, signerName;
    HashAlgo hashAlgo = HashAlgo::SHA256;
    CertLevel certLevel = CertLevel::NotCertified;

    // Timestamp
    std::string tsaUrl, tsaUser, tsaPass, tsaPolicyOid;
    HashAlgo tsaHashAlgo = HashAlgo::SHA256;

    // Long-term validation
    bool ocsp = false;
    bool crl = false;

    // Output encryption
    EncryptionMode encryption = EncryptionMode::None;
    std::string ownerPassword, userPassword;
    bool permPrinting = true, permModify = false, permCopy = true,
         permAnnotate = false;

    VisibleSignature visible;
    bool quiet = false;
};

struct VerifyOptions {
    std::string inputPath;
    std::string trustedCertsDir;
};

const char* hashAlgoName(HashAlgo);  // "SHA256" etc.

} // namespace jsp
