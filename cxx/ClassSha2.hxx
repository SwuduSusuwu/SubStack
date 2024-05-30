/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#pragma once
#ifndef INCLUDES_cxx_ClassSha2_hxx
#define INCLUDES_cxx_ClassSha2_hxx
#include <string> /* std::string */
#include "ClassPortableExecutable.hxx" /* FileBytecode */
namespace Susuwu {
/* Uses https://www.rfc-editor.org/rfc/rfc6234#section-8.2.2 */
/* const */ std::string /* 128 bits, not null-terminated */ Sha1(const FileBytecode &bytecode);
/* const */ std::string /* 256 bits, not null-terminated */ Sha256(const FileBytecode &bytecode);
/* const */ std::string /* 512 bits, not null-terminated */ Sha512(const FileBytecode &bytecode);
static auto Sha2 = Sha256; /* To compress, apps can execute `Sha2 = Sha1;`. To double hash sizes, execute `Sha2 = Sha512;`. (Warning: this does not recompute hashes which exist) */
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassSha2_hxx */

