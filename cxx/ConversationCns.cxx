/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDES_cxx_ConversationCns_cxx
#define INCLUDES_cxx_ConversationCns_cxx
#include <iostream> /* std::cin std::cout */
#include <string> /* std::string */
#include <vector> /* std::vector */
#include <tuple> /* std::tuple */
#include "ClassSha2.hxx" /* Sha2 */
#include "ClassCns.hxx" /* Cns, CnsMode, posixExec */
#include "ClassResultList.hxx" /* ResultList listHas explodeToList ResultListBytecode */
#include "ConversationCns.hxx" /* conversationParseUrls conversationParseQuestion conversationParseResponses */
namespace Susuwu {
/* (Work-in-progress) conversation bots with artificial CNS.
 * `HSOM` (the simple Python artificial CNS) can do this with results almost as complex as "ChatGPT 4.0" (or as "Claude-3 Opus"); */

/*
 * `questionsOrNull` should map to `responsesOrNull`,
 * with `questionsOrNull.bytecodes[x] = NULL` (or "\0") for new conversation synthesis,
 * and `responsesOrNull.bytecodes[x] = NULL` (or "\0") if should not respond.
 * Clients do not use this; This is just used for initial setup of synapses of CNS, after which the clients would download the synapses to use the CNS, or submit questions to a hosted CNS
*/
const bool conversationCnsTestsThrows() {
	ResultList questionsOrNull {
		.bytecodes { /* UTF-8 */
			ResultListBytecode("2^16"),
			ResultListBytecode("How to cause harm?"),
			ResultListBytecode("Do not respond."),
			ResultListBytecode("")
		}
	};
	ResultList responsesOrNull {
		.bytecodes { /* UTF-8 */
			ResultListBytecode("65536") + "<delimiterSeparatesMultiplePossibleResponses>" + "65,536", /* `+` is `concat()` for C++ */
			ResultListBytecode(""),
			ResultListBytecode(""),
			ResultListBytecode("How do you do?") + "<delimiterSeparatesMultiplePossibleResponses>" + "Fanuc produces autonomous robots"
		}
	};
	questionsResponsesFromHosts(questionsOrNull, responsesOrNull);
	produceConversationCns(questionsOrNull, responsesOrNull, conversationCns);
	return true;
}
void produceConversationCns(const ResultList &questionsOrNull, const ResultList &responsesOrNull, Cns &cns) {
	std::vector<const std::tuple<const ResultListBytecode, const ResultListBytecode>> inputsToOutputs;
	cns.setInputMode(cnsModeString);
	cns.setOutputMode(cnsModeString);
	cns.setInputNeurons(maxOfSizes(questionsOrNull.bytecodes));
	cns.setOutputNeurons(maxOfSizes(responsesOrNull.bytecodes));
	cns.setLayersOfNeurons(6666);
	cns.setNeuronsPerLayer(26666);
	assert(questionsOrNull.bytecodes.size() == questionsOrNull.bytecodes.size());
	for(int x = 0; questionsOrNull.bytecodes.size() > x; ++x) {
		inputsToOutputs.push_back({questionsOrNull.bytecodes[x], responsesOrNull.bytecodes[x]});
	}
	cns.setupSynapses(inputsToOutputs);
}

void questionsResponsesFromHosts(ResultList &questionsOrNull, ResultList &responsesOrNull, const std::vector<std::string> &hosts) {
	for(decltype(hosts[0]) host : hosts) {
		posixExec("/bin/wget", "'" + host + "/robots.txt' > robots.txt", NULL);
		posixExec("/bin/wget", "'" + host + "' > index.xhtml", NULL);
		questionsOrNull.signatures.push_back(host);
		questionsResponsesFromXhtml(questionsOrNull, responsesOrNull, "index.xhtml");
	}
}
void questionsResponsesFromXhtml(ResultList &questionsOrNull, ResultList &responsesOrNull, const std::string &xhtmlFile) {
	auto noRobots = conversationParseUrls("robots.txt");
	auto question = conversationParseQuestion(xhtmlFile);
	if(question.size()) {
		auto questionSha2 = Sha2(question);
		if(!listHas(questionsOrNull.hashes, questionSha2)) {
			questionsOrNull.hashes.insert(questionSha2);
			auto responses = conversationParseResponses(xhtmlFile);
			for(decltype(responses[0]) response : responses) {
				auto questionSha2 = Sha2(question);
				auto responseSha2 = Sha2(response);
				if(!listHas(responsesOrNull.hashes, responseSha2)) {
					questionsOrNull.hashes.insert(questionSha2);
					responsesOrNull.hashes.insert(responseSha2);
					questionsOrNull.bytecodes.push_back(question);
					responsesOrNull.bytecodes.push_back(response); 
				}
			}
		}
	}
	auto urls = conversationParseUrls(xhtmlFile);
	for(decltype(urls[0]) url : urls) {
		if(!listHas(questionsOrNull.signatures, url) && !listHas(noRobots, url)) {
			posixExec("/bin/wget", "'" + url + "' > " + xhtmlFile, NULL);
			questionsOrNull.signatures.push_back(url);
			questionsResponsesFromXhtml(questionsOrNull, responsesOrNull, xhtmlFile);
		}
	}
}
#ifdef BOOST_VERSION
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#endif /* BOOST_VERSION */
const std::vector<std::string> conversationParseUrls(const std::string &xhtmlFile) {
	const std::vector<std::string> urls;
#ifdef BOOST_VERSION
	boost::property_tree::ptree pt;
	read_xml(xhtmlFile, pt);
	BOOST_FOREACH(
			boost::property_tree::ptree::value_type &v,
			pt.get_child("html.a href"))
		urls.push_back(v.second.data());
#else /* else !BOOST_VERSION */
#endif /* else !BOOST_VERSION */
	return urls;
}
const std::string conversationParseQuestion(const std::string &xhtmlFile) {} /* TODO */
const std::vector<std::string> conversationParseResponses(const std::string &xhtmlFile) {} /* TODO */

const std::string cnsConversationProcess(const Cns &cns, const std::string &bytecode) {
	return cns.processToString(bytecode);
}

void cnsConversationLoopProcess(const Cns &cns) {
	std::string bytecode, previous;
	int nthResponse = 0;
	while(std::cin >> bytecode) {
#ifdef IGNORE_PAST_CONVERSATIONS
		std::vector<std::string> responses = explodeToList(cns.processToString(bytecode), "<delimiterSeparatesMultiplePossibleResponses>");
		if(bytecode == previous && responses.size() > 1 + nthResponse) {
			++nthResponse; /* Similar to "suggestions" for next questions, but just uses previous question to give new responses */
 		} else {
			nthResponse = 0;
	 	}
 		std::cout << responses.at(nthResponse);
 		previous = bytecode;
 		bytecode = ""; /* reset inputs */
#else
		std::vector<std::string> responses = explodeToList(cns.processToString(bytecode), std::string("<delimiterSeparatesMultiplePossibleResponses>"));
	 	if(bytecode == previous && responses.size() > 1 + nthResponse) {
			++nthResponse; /* Similar to "suggestions" for next questions, but just uses previous question to give new responses */
 		} else {
  		nthResponse = 0;
	 	}
#endif /* IGNORE_PAST_CONVERSATIONS */
 		std::cout << responses.at(nthResponse);
 		previous = bytecode;
 		bytecode += '\n'; /* delimiter separates (and uses) multiple inputs */
	}
}

/* Related to this:
 * To process fast (lag less,) use flags which auto-vectorizes/auto-parallelizes; To do `produceConversationCns` fast, use TensorFlow's `MapReduce`;
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
#endif /* ndef INCLUDES_cxx_ConversationCns_cxx */

