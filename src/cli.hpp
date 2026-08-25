// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#pragma once

#include "options.hpp"
#include <string>
#include <variant>

namespace jsp {

enum class Command { Sign, Verify, Help, Version };

struct ParsedArgs {
    Command command = Command::Help;
    SignOptions sign;
    VerifyOptions verify;
};

// Parses argv into a ParsedArgs. Throws std::runtime_error with a usage-oriented
// message on invalid input.
ParsedArgs parseArgs(int argc, char** argv);

// Prints top-level usage to stdout.
void printUsage();

} // namespace jsp
