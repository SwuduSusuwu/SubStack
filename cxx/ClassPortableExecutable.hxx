/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#pragma once
#ifndef INCLUDES_cxx_ClassPortableExecutable_hxx
#define INCLUDES_cxx_ClassPortableExecutable_hxx
#include "ClassObject.hxx" /* Object */
#include <string> /* std::string */
#include <fstream> /* std::ifstream */
#include <sstream> /* std::stringstream */
namespace Susuwu {
typedef std::string FilePath; /* TODO: `std::char_traits<unsigned char>`, `std::basic_string<unsigned char>("string literal")` */
typedef FilePath FileBytecode; /* Uses `std::string` for bytecode (versus `std::vector`) because:
 * "If you are going to use the data in a string like fashon then you should opt for std::string as using a std::vector may confuse subsequent maintainers. If on the other hand most of the data manipulation looks like plain maths or vector like then a std::vector is more appropriate." -- https://stackoverflow.com/a/1556294/24473928
*/
typedef FilePath FileHash; /* TODO: `std::unordered_set<std::basic_string<unsigned char>>` */
typedef class PortableExecutable : Object {
/* TODO: union of actual Portable Executable (Microsoft) + ELF (Linux) specifications */
public:
	PortableExecutable(FilePath path_ = "") : path(path_) {}
	PortableExecutable(FilePath path_, FileBytecode bytecode_) : path(path_), bytecode(bytecode_) {}
/*TODO: overload on typedefs which map to the same types:	PortableExecutable(FilePath path_, std::string hex_) : path(path_), hex(hex_) {} */
	const std::string getName() const {return "Susuwu::class PortableExecutable";}
	FilePath path; /* Suchas "C:\Program.exe" or "/usr/bin/library.so" */
	FileBytecode bytecode; /* compiled programs; bytecode */
	std::string hex; /* `hexdump(path)`, hexadecimal, for C string functions */
} PortableExecutable;
typedef class PortableExecutableBytecode : public PortableExecutable {
public:
	PortableExecutableBytecode(FilePath path_) : input(path_) {path = path_; if(input.good()) {buffer << input.rdbuf(); path = path_; bytecode = buffer.str();}}
	std::ifstream input;
	std::stringstream buffer;
} PortableExecutableBytecode;
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassPortableExecutable_hxx */

