/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDES_cxx_ClassSha2_cxx
#define INCLUDES_cxx_ClassSha2_cxx
#include "ClassPortableExecutable.hxx" /* FileBytecode FileHash */
#include "ClassSha2.hxx"
extern "C" {
/* Uses https://www.rfc-editor.org/rfc/rfc6234#section-8.2.2 */
#include "../c/rfc6234/sha.h" /* SHA256HashSize, SHA256Context, SHA256Reset, SHA256Input, SHA256Result, SHA1*, SHA512*  */
}
namespace Susuwu {
/* const */ FileHash /* 128 bits, not null-terminated */ Sha1(const FileBytecode &bytecode) {
	FileHash result;
	SHA1Context context;
	result.reserve(SHA1HashSize);
	SHA1Reset(&context); /* If undefined, link sha1.o */
	SHA1Input(&context, reinterpret_cast<const unsigned char *>(bytecode.c_str()), bytecode.size());
	SHA1Result(&context, const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(result.c_str())));
	return result;
}

/* const */ FileHash /* 256 bits, not null-terminated */ Sha256(const FileBytecode &bytecode) {
	FileHash result;
	SHA256Context context;
	result.reserve(SHA256HashSize);
	SHA256Reset(&context); /* If undefined, link sha224-256.o */
	SHA256Input(&context, reinterpret_cast<const unsigned char *>(bytecode.c_str()), bytecode.size());
	SHA256Result(&context, const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(result.c_str())));
	return result;
}

/* const */ FileHash /* 512 bits, not null-terminated */ Sha512(const FileBytecode &bytecode) {
	FileHash result;
	SHA512Context context;
	result.reserve(SHA512HashSize);
	SHA512Reset(&context); /* If undefined, link sha384-512.o */
	SHA512Input(&context, reinterpret_cast<const unsigned char *>(bytecode.c_str()), bytecode.size());
	SHA512Result(&context, const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(result.c_str())));
	return result;
}
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassSha2_cxx */

