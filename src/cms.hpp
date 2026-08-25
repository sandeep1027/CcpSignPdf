// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#pragma once

#include "keystore.hpp"
#include "options.hpp"
#include "timestamp.hpp"
#include <string>
#include <vector>

namespace jsp {

// Builds a detached CMS/PKCS#7 SignedData over `content`, signed with `ks` using
// the given hash algorithm. Standard signed attributes (content-type,
// signing-time, message-digest) are included.
//
// If tsa.url is non-empty, an RFC 3161 timestamp token is requested over the
// signature value and embedded as an id-aa-timeStampToken unsigned attribute.
//
// Returns the DER-encoded ContentInfo for the PDF /Contents entry.
std::vector<unsigned char> buildDetachedCms(
    const Keystore& ks,
    const std::vector<unsigned char>& content,
    HashAlgo hashAlgo,
    const TsaParams& tsa);

} // namespace jsp
