// SPDX-License-Identifier: MIT
// Copyright (c) 2026 CcpSignPdf Authors. Licensed under the MIT License.
// This notice must be preserved in all copies or substantial portions.
#include "cli.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <algorithm>

namespace jsp {

namespace {

std::string need(int argc, char** argv, int& i, const std::string& flag) {
    if (i + 1 >= argc) throw std::runtime_error("missing value for " + flag);
    return argv[++i];
}
double needD(int argc, char** argv, int& i, const std::string& f) {
    return std::stod(need(argc, argv, i, f));
}

std::string upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return s;
}

HashAlgo parseHash(const std::string& v) {
    std::string u = upper(v);
    if (u == "SHA1") return HashAlgo::SHA1;
    if (u == "SHA256") return HashAlgo::SHA256;
    if (u == "SHA384") return HashAlgo::SHA384;
    if (u == "SHA512") return HashAlgo::SHA512;
    if (u == "RIPEMD160") return HashAlgo::RIPEMD160;
    throw std::runtime_error("unknown hash algorithm: " + v);
}

CertLevel parseCertLevel(const std::string& v) {
    int n = std::stoi(v);
    if (n < 0 || n > 3) throw std::runtime_error("cert-level must be 0-3");
    return static_cast<CertLevel>(n);
}

RenderMode parseRender(const std::string& v) {
    std::string u = upper(v);
    if (u == "DESCRIPTION_ONLY") return RenderMode::DescriptionOnly;
    if (u == "GRAPHIC_AND_DESCRIPTION") return RenderMode::GraphicAndDescription;
    if (u == "SIGNAME_AND_DESCRIPTION") return RenderMode::SignerNameAndDescription;
    throw std::runtime_error("unknown render mode: " + v);
}

} // namespace

void printUsage() {
    std::cout <<
"ccpsignpdf - digitally sign and verify PDFs (JSignPdf-style CLI)\n\n"
"USAGE:\n"
"  ccpsignpdf sign   [options] --in <pdf> --keystore <p12> --pass <pw>\n"
"  ccpsignpdf verify [options] --in <pdf>\n"
"  ccpsignpdf --help | --version\n\n"
"INPUT / OUTPUT:\n"
"  --in <path>            Input PDF (required)\n"
"  --out <path>           Explicit output path\n"
"  --out-dir <dir>        Output directory (JSignPdf -d)\n"
"  --out-prefix <s>       Output filename prefix (-op)\n"
"  --out-suffix <s>       Output filename suffix (-os, default _signed)\n"
"  --append               Add signature preserving prior revisions (-a)\n"
"  --quiet                Suppress success output (-q)\n\n"
"KEYSTORE:\n"
"  --keystore <path>      PKCS#12 file, or PKCS#11 module path\n"
"  --pass <pw>            Keystore password / PKCS#11 PIN\n"
"  --ks-type <PKCS12|PKCS11>   Keystore type (default PKCS12)\n"
"  --alias <name>         Key alias / PKCS#11 key label\n"
"  --key-pass <pw>        Separate key password\n\n"
"SIGNATURE:\n"
"  --reason <t> --location <t> --contact <t> --name <t>\n"
"  --hash <SHA1|SHA256|SHA384|SHA512|RIPEMD160>   (default SHA256)\n"
"  --cert-level <0-3>     0 none,1 no-changes,2 form-fill,3 form+annots\n\n"
"TIMESTAMP (RFC 3161):\n"
"  --tsa-url <url> [--tsa-user u --tsa-pass p]\n"
"  --tsa-policy <oid>     TSA policy OID\n"
"  --tsa-hash <algo>      TSA digest algorithm (default SHA256)\n\n"
"LONG-TERM VALIDATION:\n"
"  --ocsp                 Embed OCSP responses into /DSS\n"
"  --crl                  Embed CRLs into /DSS\n\n"
"VISIBLE SIGNATURE:\n"
"  --visible --page <n> --rect <llx lly urx ury>\n"
"  --all-pages            Stamp the visible appearance on every page\n"
"  --render <DESCRIPTION_ONLY|GRAPHIC_AND_DESCRIPTION|SIGNAME_AND_DESCRIPTION>\n"
"  --l2-text <t> --l4-text <t> --font-size <n> --bg-image <path>\n\n"
"OUTPUT ENCRYPTION:\n"
"  --encrypt              Enable password encryption of the output\n"
"  --owner-pass <pw> --user-pass <pw>\n"
"  --no-print --no-copy --allow-modify --allow-annotate\n\n"
"VERIFY:\n"
"  --in <path> [--trusted <dir-of-PEM-CAs>]\n";
}

ParsedArgs parseArgs(int argc, char** argv) {
    ParsedArgs out;
    if (argc < 2) { out.command = Command::Help; return out; }

    std::string cmd = argv[1];
    if (cmd == "--help" || cmd == "-h") { out.command = Command::Help; return out; }
    if (cmd == "--version" || cmd == "-v") { out.command = Command::Version; return out; }

    if (cmd == "sign") {
        out.command = Command::Sign;
        SignOptions& s = out.sign;
        for (int i = 2; i < argc; ++i) {
            std::string a = argv[i];
            if      (a == "--in")         s.inputPath    = need(argc, argv, i, a);
            else if (a == "--out")        s.outputPath   = need(argc, argv, i, a);
            else if (a == "--out-dir")    s.outDir       = need(argc, argv, i, a);
            else if (a == "--out-prefix") s.outPrefix    = need(argc, argv, i, a);
            else if (a == "--out-suffix") s.outSuffix    = need(argc, argv, i, a);
            else if (a == "--append")     s.append       = true;
            else if (a == "--quiet")      s.quiet        = true;
            else if (a == "--keystore")   s.keystorePath = need(argc, argv, i, a);
            else if (a == "--pass")       s.keystorePass = need(argc, argv, i, a);
            else if (a == "--ks-type")    s.keystoreType = (upper(need(argc, argv, i, a)) == "PKCS11")
                                                            ? KeystoreType::PKCS11 : KeystoreType::PKCS12;
            else if (a == "--alias")      s.keyAlias     = need(argc, argv, i, a);
            else if (a == "--key-pass")   s.keyPass      = need(argc, argv, i, a);
            else if (a == "--reason")     s.reason       = need(argc, argv, i, a);
            else if (a == "--location")   s.location     = need(argc, argv, i, a);
            else if (a == "--contact")    s.contactInfo  = need(argc, argv, i, a);
            else if (a == "--name")       s.signerName   = need(argc, argv, i, a);
            else if (a == "--hash")       s.hashAlgo     = parseHash(need(argc, argv, i, a));
            else if (a == "--cert-level") s.certLevel    = parseCertLevel(need(argc, argv, i, a));
            else if (a == "--tsa-url")    s.tsaUrl       = need(argc, argv, i, a);
            else if (a == "--tsa-user")   s.tsaUser      = need(argc, argv, i, a);
            else if (a == "--tsa-pass")   s.tsaPass      = need(argc, argv, i, a);
            else if (a == "--tsa-policy") s.tsaPolicyOid = need(argc, argv, i, a);
            else if (a == "--tsa-hash")   s.tsaHashAlgo  = parseHash(need(argc, argv, i, a));
            else if (a == "--ocsp")       s.ocsp         = true;
            else if (a == "--crl")        s.crl          = true;
            else if (a == "--visible")    s.visible.enabled = true;
            else if (a == "--all-pages")  { s.visible.enabled = true; s.visible.allPages = true; }
            else if (a == "--page")       s.visible.page = std::stoi(need(argc, argv, i, a));
            else if (a == "--render")     s.visible.renderMode = parseRender(need(argc, argv, i, a));
            else if (a == "--l2-text")    s.visible.l2Text = need(argc, argv, i, a);
            else if (a == "--l4-text")    s.visible.l4Text = need(argc, argv, i, a);
            else if (a == "--font-size")  s.visible.fontSize = needD(argc, argv, i, a);
            else if (a == "--bg-image")   s.visible.bgImagePath = need(argc, argv, i, a);
            else if (a == "--rect") {
                s.visible.llx = needD(argc, argv, i, a);
                s.visible.lly = needD(argc, argv, i, a);
                s.visible.urx = needD(argc, argv, i, a);
                s.visible.ury = needD(argc, argv, i, a);
            }
            else if (a == "--encrypt")    s.encryption   = EncryptionMode::Password;
            else if (a == "--owner-pass") s.ownerPassword= need(argc, argv, i, a);
            else if (a == "--user-pass")  s.userPassword = need(argc, argv, i, a);
            else if (a == "--no-print")     s.permPrinting = false;
            else if (a == "--no-copy")      s.permCopy     = false;
            else if (a == "--allow-modify") s.permModify   = true;
            else if (a == "--allow-annotate") s.permAnnotate = true;
            else throw std::runtime_error("unknown option: " + a);
        }
        if (s.inputPath.empty() || s.keystorePath.empty() || s.keystorePass.empty())
            throw std::runtime_error("sign requires --in, --keystore, --pass");
        return out;
    }

    if (cmd == "verify") {
        out.command = Command::Verify;
        VerifyOptions& v = out.verify;
        for (int i = 2; i < argc; ++i) {
            std::string a = argv[i];
            if      (a == "--in")      v.inputPath = need(argc, argv, i, a);
            else if (a == "--trusted") v.trustedCertsDir = need(argc, argv, i, a);
            else throw std::runtime_error("unknown option: " + a);
        }
        if (v.inputPath.empty()) throw std::runtime_error("verify requires --in");
        return out;
    }

    throw std::runtime_error("unknown command: " + cmd);
}

} // namespace jsp
