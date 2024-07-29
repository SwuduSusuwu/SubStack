/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDES_cxx_main_cxx
#define INCLUDES_cxx_main_cxx
#include "AssistantCns.hxx" /* assistantCnsTestsThrows */
#include "ClassSys.hxx" /* execves execvex */
#include "Macros.hxx" /* ASSUME EXPECTS ENSURES NOEXCEPT NORETURN */
#include "VirusAnalysis.hxx" /* virusAnalysisTestsThrows */
#include <cstdlib> /* exit EXIT_SUCCESS */
#include <iostream> /* cout flush endl */
namespace Susuwu {
void noExcept() NOEXCEPT;
NORETURN void noReturn();
void noExcept() NOEXCEPT {std::cout << std::flush;}
void noReturn()  {exit(0);}
int testHarnesses() EXPECTS(true) ENSURES(true) {
	std::cout << "cxx/Macros.hxx: " << std::flush;
	ASSUME(true);
	noExcept();
	std::cout << "pass" << std::endl;
	std::cout << "execves(): " << std::flush;
	(EXIT_SUCCESS == execves({"/bin/echo", "pass"})) || std::cout << "error" << std::endl;
	std::cout << "execvex(): " << std::flush;
	(EXIT_SUCCESS == execvex("/bin/echo pass")) || std::cout << "error" << std::endl;
	std::cout << "virusAnalysisTestsThrows(): " << std::flush;
	if(virusAnalysisTestsThrows()) {
		std::cout << "pass" << std::endl;
	} else {
		std::cout << "error" << std::endl;
	}
	std::cout << "assistantCnsTestsThrows(): " << std::flush;
	if(assistantCnsTestsThrows()) {
		std::cout << "pass" << std::endl;
	} else {
		std::cout << "error" << std::endl;
	}
	noReturn();
}
}; /* namespace Susuwu */
int main(int argc, const char **args) {
	return Susuwu::testHarnesses();
}
#endif /* ndef INCLUDES_cxx_main_cxx */

