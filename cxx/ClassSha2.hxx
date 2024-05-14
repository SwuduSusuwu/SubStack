/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#pragma once
#ifndef INCLUDES_cxx_ClassSha2_hxx
#define INCLUDES_cxx_ClassSha2_hxx
#include <string> /* std::string */
#include "ClassPortableExecutable.hxx" /* FileBytecode */
/* TODO: Unimplemented, is just a stub to compile; you should replace with official implementation of Sha2. 
 * https://www.rfc-editor.org/rfc/rfc6234#section-8.2.2 */
namespace Susuwu {
/* const */ std::string /* 256 bits, not null-terminated */ Sha2(const FileBytecode &bytecode);
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassSha2_hxx */

