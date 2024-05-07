#include <string>
#include "ClassCns.c++" /* Cns, CnsMode */
#include "ClassResultList.c++" /* ResultList */
/* Pseudocodes (work-in-progress) of conversation bots with artificial CNS ("HSOM" (the simple Python artificial CNS) is enough to do this), which should have results almost as complex as "ChatGPT 4.0" (or as "Claude-3 Opus"); */
namespace Susuwu {
/*
 * `questionsOrNull` should map to `responsesOrNull`,
 * with `questionsOrNull->bytes[x] = NULL` (or "\0") for new conversation synthesis,
 * and `responsesOrNull->bytes[x] = NULL` (or "\0") if should not respond.
 * Clients do not use this; This is just used for initial setup of synapses of CNS, after which the clients would download the synapses to use the CNS, or submit questions to a hosted CNS
*/
ResultList questionsOrNull(
 bytes = { /* UTF-8 */
  "2^16",
  "How to cause harm?",
  "Do not respond.",
  "",
  ...
  QuoraQuestions, /* Uses quora.com databases */
  StackOverflowQuestions, /* Uses stackoverflow.com databases */
  SuperUserQuestions, /* Uses superuser.com databases */
  WikipediaPageDescriptions, /* Uses wikipedia.org databases */
  GithubRepoDescriptions, /* Uses github.com databases */
  ...
 }
);
ResultList responsesOrNull(
 bytes = { /* UTF-8 */
  "65536" + "<delimiterSeparatesMultiplePossibleResponses>" + "65,536", /* `+` is `concat()` for C++ */
  "",
  "",
  "How do you do?" + "<delimiterSeparatesMultiplePossibleResponses>" + "Fanuc produces autonomous robots",
  ...
  QuoraResponses,
  StackOverflowResponses,
  SuperUserResponses,
  GithubRepoSources,
  ...
 }
);

void setupConversationCns(cns, &questionsOrNull, &responsesOrNull);
void setupConversationCns(Cns *cns,
 const ResultList *questionsOrNull, /* Expects `questionsOrNull>bytes[x] = NULL` if no question (new conversation synthesis) */
 const ResultList *responsesOrNull /* Expects `responsesOrNull->bytes[x] = NULL` if should not respond */
) {
 vector<const std::string> inputsOrNull, outputsOrNull;
 cns->setInputMode(cnsModeString);
 cns->setOutputMode(cnsModeString);
 cns->setInputNeurons(maxOfSizes(questionsOrNull->bytes));
 cns->setOutputNeurons(maxOfSizes(responsesOrNull->bytes));
 cns->setLayersOfNeurons(6666);
 cns->setNeuronsPerLayer(26666);
 assert(questionsOrNull->bytes.length() == questionsOrNull->bytes.length());
 for(int x = 0; questionsOrNull->bytes.length() > x; ++x) {
  inputsOrNull.pushback(questionsOrNull->bytes[x]);
  outputsOrNull.pushback(responsesOrNull->bytes[x]);
 }
 cns->setTrainingInputs(inputsOrNull);
 cns->setTrainingOutputs(outputsOrNull);
 cns->setupSynapses();
}

const std::string cnsConversation(const Cns *cns, const std::string &bytes) {
 return cns->process<std::string, std::string>(bytes);
}

void cnsMultipleInputsProcess(const Cns *cns) {
 std::string utf8Bytes, previous;
 int nthResponse = 0;
#ifdef IGNORE_PAST_CONVERSATIONS
 while(utf8Bytes << std::cin) {
 vector<std::string> responses = explode(cns->process<std::string, std::string>(bytes), "<delimiterSeparatesMultiplePossibleResponses>");
  if(utf8Bytes == previous && responses.size() > 1 + nthResponse) {
   ++nthResponse; /* Similar to "suggestions" for next questions, but just uses previous question to give new responses */
  } else {
   nthResponse = 0;
  }
  std::cout << responses.at(nthResponse);
  previous = utf8Bytes;
  utf8Bytes = ""; /* reset inputs */
 }
#else
 while(utf8Bytes << std::cin) {
 vector<std::string> responses = explode(cns->process<std::string, std::string>(bytes), "<delimiterSeparatesMultiplePossibleResponses>");
  if(utf8Bytes == previous && responses.size() > 1 + nthResponse) {
   ++nthResponse; /* Similar to "suggestions" for next questions, but just uses previous question to give new responses */
  } else {
   nthResponse = 0;
  }
#endif /* IGNORE_PAST_CONVERSATIONS */
  std::cout << responses.at(nthResponse);
  previous = utf8Bytes;
  utf8Bytes << '\n'; /* delimiter separates (and uses) multiple inputs */
 }
}

/* Pseudocodes of howto setup `questionsOrNull` + `responsesOrNull`: */
std::vector<std::string> hosts = {
 "https://stackexchange.com",
 "https://superuser.com",
 "https://quora.com",
 ...
/* Wikipedia is a special case; has compressed downloads of databases ( https://wikipedia.org/wiki/Wikipedia:Database_download ) */
/* Github is a special case; has compressed downloads of repositories ( https://docs.github.com/en/get-started/start-your-journey/downloading-files-from-github ) */
};
foreach(hosts as host) {
 exec("wget '" + host + "/robots.txt' > robots.txt");
 identifiers = extractIdentifiers("robots.txt");
 foreach(identifiers as identifier) {
  questionsOrNull.identifiers.pushback(identifier);
 }
 if(host not in questionsOrNull.identifiers) {
  questionsOrNull.identifiers.pushback(host);
  exec("wget '" + host + "' > source.txt");
  extraHosts = extractIdentifiers("source.txt");
  foreach(extraHosts as extraHost) {
   hosts.pushback(extraHost);
  }
  question = extractQuestion("source.txt");
  if(question) {
   auto questionSha2 = sha2(question);
   if(questionSha2 not in questionsOrNull.hashes) {
    questionsOrNull.hashes.pushback(questionSha2);
    responses = extractResponses("source.txt");
    foreach(responses as response) {
     auto questionSha2 = sha2(question);
     if(responseSha2 not in responseOrNull.hashes) {
      responsesOrNull.hashes.pushback(responseSha2);
      questionsOrNull.bytes.pushback(question);
      responsesOrNull.bytes.pushback(response); 
     }
    }
   }
  }
 }
}

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
};

