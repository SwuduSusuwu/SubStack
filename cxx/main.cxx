/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDES_cxx_main_cxx
#define INCLUDES_cxx_main_cxx
#include "VirusAnalysis.hxx" /* virusAnalysisTestsThrows */
#include "ConversationCns.hxx" /* conversationCnsTestsThrows */
#include "Macros.hxx" /* ASSUME EXPECTS ENSURES NOEXCEPT NORETURN */
#include <iostream> /* cout flush endl */
#include <stdlib.h> /* exit */
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
	std::cout << "virusAnalysisTestsThrows(): " << std::flush;
	if(virusAnalysisTestsThrows()) {
		std::cout << "pass" << std::endl;
	} else {
		std::cout << "error" << std::endl;
	}
	std::cout << "conversationCnsTestsThrows(): " << std::flush;
	if(conversationCnsTestsThrows()) {
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

