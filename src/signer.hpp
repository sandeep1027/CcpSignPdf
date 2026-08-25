// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#pragma once

#include "options.hpp"

namespace jsp {

// Signs a PDF according to `opt`. Returns the path of the signed output
// (resolved from --out or from dir/prefix/suffix). Throws on failure.
std::string signPdf(const SignOptions& opt);

} // namespace jsp
