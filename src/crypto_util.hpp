// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#pragma once

#include "options.hpp"
#include <openssl/evp.h>

namespace jsp {

// Maps our HashAlgo enum to an OpenSSL EVP_MD. Throws if unsupported.
const EVP_MD* evpMd(HashAlgo algo);

} // namespace jsp
