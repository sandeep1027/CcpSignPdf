// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#include "crypto_util.hpp"
#include <stdexcept>

namespace jsp {

const char* hashAlgoName(HashAlgo a) {
    switch (a) {
        case HashAlgo::SHA1:      return "SHA1";
        case HashAlgo::SHA256:    return "SHA256";
        case HashAlgo::SHA384:    return "SHA384";
        case HashAlgo::SHA512:    return "SHA512";
        case HashAlgo::RIPEMD160: return "RIPEMD160";
    }
    return "SHA256";
}

const EVP_MD* evpMd(HashAlgo a) {
    const EVP_MD* md = nullptr;
    switch (a) {
        case HashAlgo::SHA1:      md = EVP_sha1();      break;
        case HashAlgo::SHA256:    md = EVP_sha256();    break;
        case HashAlgo::SHA384:    md = EVP_sha384();    break;
        case HashAlgo::SHA512:    md = EVP_sha512();    break;
        case HashAlgo::RIPEMD160: md = EVP_ripemd160(); break;
    }
    if (!md) throw std::runtime_error("hash algorithm unavailable in this OpenSSL build");
    return md;
}

} // namespace jsp
