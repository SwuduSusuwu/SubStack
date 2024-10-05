/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDES_cxx_main_cxx
#define INCLUDES_cxx_main_cxx
#include "AssistantCns.hxx" /* assistantCnsTestsNoexcept */
#include "ClassSha2.hxx" /* classSha2TestsNoexcept */
#include "ClassSys.hxx" /* execves execvex templateCatchAll */
#include "Macros.hxx" /* ASSUME EXPECTS ENSURES NOEXCEPT NORETURN */
#include "VirusAnalysis.hxx" /* virusAnalysisTestsNoexcept */
#include <cstdlib> /* exit EXIT_SUCCESS */
#include <iostream> /* std::cout std::flush std::endl */
namespace Susuwu {
void noExcept() NOEXCEPT;
NORETURN void noReturn();
void noExcept() NOEXCEPT {std::cout << std::flush;}
void noReturn() {exit(0);}
int testHarnesses() EXPECTS(true) ENSURES(true) {
	std::cout << "cxx/Macros.hxx: " << std::flush;
	ASSUME(true);
	noExcept();
	std::cout << "pass" << std::endl;
	std::cout << "execves(): " << std::flush;
	(EXIT_SUCCESS == execves({"/bin/echo", "pass"})) || std::cout << "error" << std::endl;
	std::cout << "execvex(): " << std::flush;
	(EXIT_SUCCESS == execvex("/bin/echo pass")) || std::cout << "error" << std::endl;
	std::cout << "classSha2TestsNoexcept(): " << std::flush;
	std::cout << (classSha2TestsNoexcept() ? "pass" : "error") << std::endl;
	std::cout << "virusAnalysisTestsNoexcept(): " << std::flush;
	if(virusAnalysisTestsNoexcept()) {
		std::cout << "pass" << std::endl;
	} else {
		std::cout << "error" << std::endl;
	}
	std::cout << "assistantCnsTestsNoexcept(): " << std::flush;
	if(assistantCnsTestsNoexcept()) {
		std::cout << "pass" << std::endl;
	} else {
		std::cout << "error" << std::endl;
	}
	noReturn();
}
}; /* namespace Susuwu */
int main(int argc, const char **args) {
	const bool classSysInitSuccess = Susuwu::classSysInit(argc, args);
	assert(classSysInitSuccess);
	return Susuwu::testHarnesses();
}
#endif /* ndef INCLUDES_cxx_main_cxx */

