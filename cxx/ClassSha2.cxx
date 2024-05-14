/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDES_cxx_ClassSha2_cxx
#define INCLUDES_cxx_ClassSha2_cxx
#include <string> /* std::string */
#include "ClassPortableExecutable.hxx" /* FileBytecode */
#include "ClassSha2.hxx"
/* TODO: Unimplemented, is just a stub (to compile); you should replace with official implementation of Sha2 ( from https://www.rfc-editor.org/rfc/rfc6234#section-8.2.2 ) */
namespace Susuwu {
/* const */ std::string /* 256 bits, not null-terminated */ Sha2(const FileBytecode &bytecode) {
	static_assert(!"TODO");
}
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassSha2_cxx */

