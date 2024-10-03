/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#pragma once
#ifndef INCLUDES_cxx_ClassSha2_hxx
#define INCLUDES_cxx_ClassSha2_hxx
#include "ClassPortableExecutable.hxx" /* FileBytecode FileHash */
namespace Susuwu {
/* Uses https://www.rfc-editor.org/rfc/rfc6234#section-8.2.2 */
/* const */ FileHash /* 128 bits, not null-terminated */ sha1(const FileBytecode &bytecode);
/* const */ FileHash /* 256 bits, not null-terminated */ sha256(const FileBytecode &bytecode);
/* const */ FileHash /* 512 bits, not null-terminated */ sha512(const FileBytecode &bytecode);
static auto sha2 = sha256; /* To compress, apps can execute `sha2 = sha1;`. To double hash sizes, execute `sha2 = sha512;`. (Notice: this does not recompute hashes which exist) */
bool classSha2Tests();
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassSha2_hxx */

