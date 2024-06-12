/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDES_cxx_main_cxx
#define INCLUDES_cxx_main_cxx
#include "VirusAnalysis.hxx" /* virusAnalysisTestsThrows */
#include "ConversationCns.hxx" /* conversationCnsTestsThrows */
#include "Macros.hxx" /* ASSUME EXPECTS ENSURES */
#include <stdio.h> /* printf */
#include <stdlib.h> /* exit */
namespace Susuwu {
int testHarnesses() EXPECTS(true) ENSURES(true) {
	ASSUME(true);
	printf("cxx/Macros.hxx: pass\n");
	if(virusAnalysisTestsThrows()) {
		printf("cxx/VirusAnalysis.hxx: pass\n");
	}
	if(conversationCnsTestsThrows()) {
		printf("cxx/ConversationCns.hxx: pass\n");
	}
	exit(0);
}
}; /* namespace Susuwu */
int main(int argc, const char **args) {
	return Susuwu::testHarnesses();
}
#endif /* ndef INCLUDES_cxx_main_cxx */

