cmake_minimum_required(VERSION 3.16)
project(CcpSignPdf
    VERSION 1.0.0
    DESCRIPTION "CcpSignPdf - JSignPdf-style PDF digital signing CLI in C++"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# ---- Options ----------------------------------------------------------------
# PKCS#11 support (hardware tokens / smartcards) requires libp11. It is opt-in
# because libp11 is not always installed. Enable with -DENABLE_PKCS11=ON.
option(ENABLE_PKCS11 "Enable PKCS#11 hardware token support (requires libp11)" OFF)

# Build a portable/standalone binary. BUILD_STATIC statically links the C++
# runtime and the third-party deps (PoDoFo/OpenSSL/curl/...) while keeping glibc
# DYNAMIC — the recommended, portable sweet spot (DNS/NSS still work for
# TSA/OCSP/CRL). Use ./build-portable.sh to produce it.
option(BUILD_STATIC "Static C++ runtime + static deps, dynamic glibc (portable)" OFF)

# FULLY_STATIC additionally passes -static (also links glibc). Only use this if
# you do NOT need runtime DNS: fully static glibc binaries cannot use NSS, so
# curl-based TSA/OCSP/CRL lookups by hostname may fail. For fully-static builds
# that still need networking, build against musl (Alpine) instead.
option(FULLY_STATIC "Also link glibc statically via -static (breaks NSS/DNS)" OFF)
if(FULLY_STATIC)
    set(BUILD_STATIC ON)
endif()

# Prefer static archives during dependency discovery when a static build is
# requested. Must run BEFORE find_package(), hence its placement here.
if(BUILD_STATIC AND NOT MSVC)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(CURL_USE_STATIC_LIBS TRUE)
endif()
if(BUILD_STATIC AND MSVC)
    # Use the static CRT so the exe does not need the VC++ redistributable.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ---- Dependencies -----------------------------------------------------------
# Static PoDoFo's exported cmake config lists these as INTERFACE_LINK_LIBRARIES
# (Fontconfig::Fontconfig, Freetype::Freetype, …). They must exist as imported
# targets BEFORE find_package(podofo), otherwise configure fails.
find_package(ZLIB REQUIRED)
find_package(PNG)
find_package(JPEG)
find_package(Freetype REQUIRED)
find_package(Fontconfig)
find_package(LibXml2 REQUIRED)

# PoDoFo >= 0.10. Its CMake package config usually exposes "podofo::podofo",
# but some builds/distros export the target as "podofo", "podofo_shared", or
# "podofo_static". Accept the package under either package name, then select
# whichever imported target actually exists. Fall back to pkg-config when no
# CMake config is installed at all.
find_package(podofo CONFIG QUIET)
if(NOT podofo_FOUND)
    find_package(PoDoFo CONFIG QUIET)
endif()

set(PODOFO_TARGET "")
foreach(_cand podofo::podofo podofo_shared podofo_static podofo)
    if(TARGET ${_cand})
        set(PODOFO_TARGET ${_cand})
        break()
    endif()
endforeach()

if(NOT PODOFO_TARGET)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PODOFO REQUIRED IMPORTED_TARGET libpodofo)
    set(PODOFO_TARGET PkgConfig::PODOFO)
endif()
message(STATUS "CcpSignPdf: using PoDoFo target '${PODOFO_TARGET}'")

# OpenSSL is used for PKCS#12 loading, detached CMS, RFC 3161 timestamps,
# and OCSP/CRL fetching for long-term validation.
find_package(OpenSSL REQUIRED)

# libcurl is used to POST timestamp/OCSP requests and GET CRLs over HTTP.
find_package(CURL REQUIRED)

# ---- Target -----------------------------------------------------------------
add_executable(ccpsignpdf
    src/main.cpp
    src/cli.cpp
    src/keystore.cpp
    src/crypto_util.cpp
    src/cms.cpp
    src/signer.cpp
    src/timestamp.cpp
    src/ltv.cpp
    src/verifier.cpp
)

target_include_directories(ccpsignpdf PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(ccpsignpdf PRIVATE
    ${PODOFO_TARGET}
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
)

# ---- Optional PKCS#11 (libp11) ----------------------------------------------
if(ENABLE_PKCS11)
    # libp11 ships a pkg-config file "libp11"; fall back to a manual search.
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBP11 QUIET libp11)
    endif()

    if(LIBP11_FOUND)
        target_include_directories(ccpsignpdf PRIVATE ${LIBP11_INCLUDE_DIRS})
        target_link_libraries(ccpsignpdf PRIVATE ${LIBP11_LIBRARIES})
    else()
        find_path(LIBP11_INCLUDE_DIR libp11.h)
        find_library(LIBP11_LIBRARY NAMES p11 libp11)
        if(NOT LIBP11_INCLUDE_DIR OR NOT LIBP11_LIBRARY)
            message(FATAL_ERROR
                "ENABLE_PKCS11=ON but libp11 was not found. Install libp11-dev "
                "(Debian/Ubuntu) or libp11 (Homebrew/vcpkg), or set "
                "LIBP11_INCLUDE_DIR and LIBP11_LIBRARY manually.")
        endif()
        target_include_directories(ccpsignpdf PRIVATE ${LIBP11_INCLUDE_DIR})
        target_link_libraries(ccpsignpdf PRIVATE ${LIBP11_LIBRARY})
    endif()

    target_compile_definitions(ccpsignpdf PRIVATE JSP_ENABLE_PKCS11)
endif()

if(MSVC)
    target_compile_options(ccpsignpdf PRIVATE /W4)
else()
    target_compile_options(ccpsignpdf PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ---- Portable / standalone linking ------------------------------------------
if(BUILD_STATIC AND NOT MSVC)
    # PoDoFo's headers need this when the library is a static archive.
    target_compile_definitions(ccpsignpdf PRIVATE PODOFO_STATIC)
    # Bundle the GCC/libstdc++ runtimes so the target never needs a matching
    # libstdc++. glibc stays dynamic (see FULLY_STATIC).
    target_link_options(ccpsignpdf PRIVATE -static-libgcc -static-libstdc++)
    find_package(Threads REQUIRED)
    target_link_libraries(ccpsignpdf PRIVATE Threads::Threads ${CMAKE_DL_LIBS} m)
    # Transitive deps of static PoDoFo / OpenSSL / curl. find_package() for the
    # named packages above often still resolves the .so; pin the .a archives
    # so the portable binary does not need them at runtime.
    foreach(_jsp_lib IN ITEMS
            fontconfig freetype png png16 jpeg xml2 z
            brotlidec brotlicommon expat uuid lzma
            icui18n icuuc icudata)
        find_library(JSP_STATIC_${_jsp_lib} NAMES ${_jsp_lib})
        if(JSP_STATIC_${_jsp_lib})
            target_link_libraries(ccpsignpdf PRIVATE ${JSP_STATIC_${_jsp_lib}})
        endif()
    endforeach()
endif()

if(FULLY_STATIC AND NOT MSVC)
    # Link glibc too. Verify the toolchain/deps actually support it first.
    include(CheckCXXSourceCompiles)
    set(CMAKE_REQUIRED_LINK_OPTIONS -static)
    check_cxx_source_compiles("int main(){return 0;}" JSP_CAN_LINK_FULLY_STATIC)
    unset(CMAKE_REQUIRED_LINK_OPTIONS)
    if(JSP_CAN_LINK_FULLY_STATIC)
        target_link_options(ccpsignpdf PRIVATE -static)
        message(WARNING
            "FULLY_STATIC: glibc is linked statically; hostname resolution via "
            "NSS will not work. TSA/OCSP/CRL fetches by hostname may fail.")
    else()
        message(WARNING
            "FULLY_STATIC requested but the toolchain lacks static libs; "
            "leaving glibc dynamic (portable across glibc >= the build host).")
    endif()
endif()

install(TARGETS ccpsignpdf RUNTIME DESTINATION bin)
