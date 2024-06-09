/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDES_cxx_main_cxx
#define INCLUDES_cxx_main_cxx
#include "VirusAnalysis.hxx" /* virusAnalysisTestsThrows */
#include "ConversationCns.hxx" /* conversationCnsTestsThrows */
#include "Macros.hxx" /* ASSUME EXPECTS ENSURES NOEXCEPT NORETURN */
#include <stdio.h> /* printf */
#include <stdlib.h> /* exit */
namespace Susuwu {
void noExcept() NOEXCEPT;
NORETURN void noReturn();
void noExcept() NOEXCEPT {printf("");}
void noReturn()  {exit(0);}
int testHarnesses() EXPECTS(true) ENSURES(true) {
	ASSUME(true);
	noExcept();
	printf("cxx/Macros.hxx: pass\n");
	if(virusAnalysisTestsThrows()) {
		printf("cxx/VirusAnalysis.hxx: pass\n");
	}
	if(conversationCnsTestsThrows()) {
		printf("cxx/ConversationCns.hxx: pass\n");
	}
	noReturn();
}
}; /* namespace Susuwu */
int main(int argc, const char **args) {
	return Susuwu::testHarnesses();
}
#endif /* ndef INCLUDES_cxx_main_cxx */

