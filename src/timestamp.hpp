// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#pragma once

#include "options.hpp"
#include <string>
#include <vector>

namespace jsp {

struct TsaParams {
    std::string url;
    std::string user;
    std::string pass;
    std::string policyOid;              // optional TSA policy OID
    HashAlgo hashAlgo = HashAlgo::SHA256;
};

// Requests an RFC 3161 timestamp token over the given content (the raw bytes to
// be hashed with params.hashAlgo, typically the signature value). Returns the
// DER-encoded TimeStampToken (a PKCS#7 ContentInfo).
std::vector<unsigned char> requestTimestampToken(
    const TsaParams& params,
    const std::vector<unsigned char>& contentToHash);

} // namespace jsp
