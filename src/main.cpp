// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#include "cli.hpp"
#include "signer.hpp"
#include "verifier.hpp"

#include <openssl/crypto.h>
#include <curl/curl.h>
#include <iostream>

namespace {
constexpr const char* kVersion = "CcpSignPdf 1.0.0";
}

int main(int argc, char** argv) {
    // Global one-time init for libcurl (OpenSSL 1.1+/3.x self-initialises).
    curl_global_init(CURL_GLOBAL_DEFAULT);

    int rc = 0;
    try {
        jsp::ParsedArgs args = jsp::parseArgs(argc, argv);
        switch (args.command) {
        case jsp::Command::Help:
            jsp::printUsage();
            break;
        case jsp::Command::Version:
            std::cout << kVersion << "\n";
            break;
        case jsp::Command::Sign: {
            std::string out = jsp::signPdf(args.sign);
            if (!args.sign.quiet) std::cout << "Signed: " << out << "\n";
            break;
        }
        case jsp::Command::Verify: {
            auto reports = jsp::verifyPdf(args.verify);
            if (reports.empty()) {
                std::cout << "No signatures found.\n";
                break;
            }
            for (const auto& r : reports) {
                std::cout << "Signature field: " << r.fieldName << "\n"
                          << "  integrity:     " << (r.integrityValid ? "VALID" : "INVALID") << "\n"
                          << "  covers file:   " << (r.coversWholeFile ? "yes" : "no (later revisions exist)") << "\n"
                          << "  timestamp:     " << (r.hasTimestamp ? "present" : "none") << "\n"
                          << "  signer:        " << r.signerSubject << "\n"
                          << "  detail:        " << r.detail << "\n";
                if (!r.integrityValid) rc = 2;
            }
            break;
        }
        }
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        rc = 1;
    }

    curl_global_cleanup();
    return rc;
}
