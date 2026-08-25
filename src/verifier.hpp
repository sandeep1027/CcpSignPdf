// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#pragma once

#include "options.hpp"
#include <string>
#include <vector>

namespace jsp {

struct SignatureReport {
    std::string fieldName;
    bool integrityValid = false;   // digest + signature check passed
    bool coversWholeFile = false;  // ByteRange spans the entire document
    bool hasTimestamp = false;
    std::string signerSubject;
    std::string detail;            // human-readable notes / errors
};

// Verifies all signatures in the given PDF. Returns one report per signature.
// If verifyOpts.trustedCertsDir is empty, chain trust is not enforced (only
// cryptographic integrity is checked).
std::vector<SignatureReport> verifyPdf(const VerifyOptions& opt);

} // namespace jsp
