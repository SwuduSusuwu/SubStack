#ifndef INCLUDE_GUARD_c__ConversationCns_h__
#define INCLUDE_GUARD_c__ConversationCns_h__
#include <iostream>
#include "ClassCns.h" /* Cns, CnsMode */
#include "ClassResultList.h" /* ResultList */
/* (Work-in-progress) conversation bots with artificial CNS ("HSOM" (the simple Python artificial CNS) is enough to do this), which should have results almost as complex as "ChatGPT 4.0" (or as "Claude-3 Opus"); */
namespace Susuwu {
/*
 * `questionsOrNull` should map to `responsesOrNull`,
 * with `questionsOrNull->bytes[x] = NULL` (or "\0") for new conversation synthesis,
 * and `responsesOrNull->bytes[x] = NULL` (or "\0") if should not respond.
 * Clients do not use this; This is just used for initial setup of synapses of CNS, after which the clients would download the synapses to use the CNS, or submit questions to a hosted CNS
*/
ResultList questionsOrNull;
ResultList responsesOrNull;

void setupConversationCns(Cns *cns,
 const ResultList *questionsOrNull, /* Expects `questionsOrNull>bytes[x] = NULL` if no question (new conversation synthesis) */
 const ResultList *responsesOrNull /* Expects `responsesOrNull->bytes[x] = NULL` if should not respond */
);

const std::string cnsConversation(const Cns *cns, const std::string &bytes);

void cnsMultipleInputsProcess(const Cns *cns); /* Inputs from std::cin, outputs to std::cout */

/* For `questionsOrNull` + `responsesOrNull` synthesis: */
std::vector<std::string> hosts; /* Universal Resources Identifiers of home pages to use for questions+responses.
 * Wikipedia is a special case; has compressed downloads of databases ( https://wikipedia.org/wiki/Wikipedia:Database_download )
 * Github is a special case; has compressed downloads of repositories ( https://docs.github.com/en/get-started/start-your-journey/downloading-files-from-github )
 */

void questionsResponsesSynthesis(ResultList *questionsOrNull, /* Sets `questionsOrNull>bytes[x] = NULL` if no question (new conversation synthesis). */
 ResultList *responsesOrNull /* Sets `responsesOrNull->bytes[x] = NULL` if should not respond */
); /* Sets `ResulstList.hashes[x] = Sha2(ResultList.bytes[x]);`, `ResultList.signatures[x] = Universal Resource Identifier` */

/* Related to this:
 * To process fast (lag less,) use flags which auto-vectorizes/auto-parallelizes; To do `setupConversationCns` fast, use TensorFlow's `MapReduce`;
 * https://swudususuwu.substack.com/p/howto-run-devices-phones-laptops
 *
 * Alternative CNS's;
 * https://swudususuwu.substack.com/p/albatross-performs-lots-of-neural
 *
 * Autonomous robots (includes responses to replies from lots of forums);
 * https://swudususuwu.substack.com/p/program-general-purpose-robots-autonomous
 *
 * Simple examples of CNS as virus analysis;
 * https://swudususuwu.substack.com/p/howto-produce-better-virus-scanners
 *
 * Due to understanding of human's consciousness, could undo problems of overpopulation and food shortages, if lots of us become uploads of consciousness (as opposed to below article of how to move whole CNS to robots);
 * https://swudususuwu.substack.com/p/want-this-physical-form-gone-so-wont
 * https://swudususuwu.substack.com/p/destructive-unreversible-upload-of
 */
}; /* namespace Susuwu */
#endif /* ndef INCLUDE_GUARD_c__ConversationCns_h__ */

