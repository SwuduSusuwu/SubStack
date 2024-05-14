/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#pragma once
#ifndef INCLUDES_cxx_ClassPortableExecutable_hxx
#define INCLUDES_cxx_ClassPortableExecutable_hxx
#include <string> /* std::string */
namespace Susuwu {
typedef std::string FilePath;
typedef std::string FileBytecode; /* Used `std::string` for bytecode (versus `vector<char>`) because:
 * "If you are going to use the data in a string like fashon then you should opt for std::string as using a std::vector may confuse subsequent maintainers. If on the other hand most of the data manipulation looks like plain maths or vector like then a std::vector is more appropriate." -- https://stackoverflow.com/a/1556294/24473928
*/
/* Todo: Unimplemented (work-in-progress) just to allow `cxx/VirusAnalysis.cxx` to compile. You should replace with official PortableExecutable/ELF headers */
typedef class PortableExecutable {
public:
	FilePath path; /* Suchas "C:\Program.exe" or "/usr/bin/library.so" */
	FileBytecode bytecode; /* compiled programs; bytecode */
	std::string hex; /* `hexdump(path)`, hexadecimal, for C string functions */
} PortableExecutable;
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassPortableExecutable_hxx */

