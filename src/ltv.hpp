// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#pragma once

#include "keystore.hpp"
#include <podofo/podofo.h>
#include <vector>

namespace jsp {

// Validation material for PAdES long-term validation (LTV).
struct ValidationInfo {
    std::vector<std::vector<unsigned char>> ocspResponses; // DER OCSP responses
    std::vector<std::vector<unsigned char>> crls;          // DER CRLs
    std::vector<std::vector<unsigned char>> certs;         // DER certificates
    bool empty() const { return ocspResponses.empty() && crls.empty() && certs.empty(); }
};

// Fetches OCSP responses and/or CRLs for the certificate chain in `ks`, based
// on each cert's AIA (OCSP) and CRL-distribution-point extensions. Network
// errors for individual sources are skipped rather than fatal.
ValidationInfo collectValidationInfo(const Keystore& ks, bool useOcsp, bool useCrl);

// Embeds the validation material into the document's /DSS dictionary
// (PAdES-B-LT). Must be called before signing so it is covered by the
// signature's ByteRange. EXPERIMENTAL: exercises low-level PoDoFo object APIs.
void embedDss(PoDoFo::PdfMemDocument& doc, const ValidationInfo& info);

} // namespace jsp
