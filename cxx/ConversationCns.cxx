/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#ifndef INCLUDES_cxx_ConversationCns_cxx
#define INCLUDES_cxx_ConversationCns_cxx
#include <iostream> /* std::cin std::cout */
#include <string> /* std::string */
#include <vector> /* std::vector */
#include <tuple> /* std::tuple */
#include "ClassSha2.hxx" /* Sha2 */
#include "ClassPortableExecutable.hxx" /* FilePath FileBytecode */
#include "ClassCns.hxx" /* Cns, CnsMode, execvex */
#include "ClassResultList.hxx" /* ResultList listMaxSize listHasValue explodeToList ResultListBytecode */
#include "ConversationCns.hxx" /* conversationParseUrls conversationParseQuestion conversationParseResponses */
/* (Work-in-progress) conversation bots with artificial CNS. */
namespace Susuwu {
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
	cns.setInputNeurons(listMaxSize(questionsOrNull.bytecodes));
	cns.setOutputNeurons(listMaxSize(responsesOrNull.bytecodes));
	cns.setLayersOfNeurons(6666);
	cns.setNeuronsPerLayer(26666);
	assert(questionsOrNull.bytecodes.size() == questionsOrNull.bytecodes.size());
	inputsToOutputs.reserve(questionsOrNull.bytecodes.size());
	for(int x = 0; questionsOrNull.bytecodes.size() > x; ++x) {
		inputsToOutputs.push_back({questionsOrNull.bytecodes[x], responsesOrNull.bytecodes[x]});
	}
	cns.setupSynapses(inputsToOutputs);
}

void questionsResponsesFromHosts(ResultList &questionsOrNull, ResultList &responsesOrNull, const std::vector<FilePath> &hosts) {
	for(auto host : hosts) {
		execvex("wget '" + host + "/robots.txt' -Orobots.txt");
		execvex("wget '" + host + "' -Oindex.xhtml");
		questionsOrNull.signatures.push_back(host);
		questionsResponsesFromXhtml(questionsOrNull, responsesOrNull, "index.xhtml");
	}
}
void questionsResponsesFromXhtml(ResultList &questionsOrNull, ResultList &responsesOrNull, const FilePath &xhtmlFile) {
	auto noRobots = conversationParseUrls("robots.txt");
	auto question = conversationParseQuestion(xhtmlFile);
	if(question.size()) {
		auto questionSha2 = Sha2(question);
		if(!listHasValue(questionsOrNull.hashes, questionSha2)) {
			questionsOrNull.hashes.insert(questionSha2);
			auto responses = conversationParseResponses(xhtmlFile);
			for(auto response : responses) {
				auto questionSha2 = Sha2(question);
				auto responseSha2 = Sha2(response);
				if(!listHasValue(responsesOrNull.hashes, responseSha2)) {
					questionsOrNull.hashes.insert(questionSha2);
					responsesOrNull.hashes.insert(responseSha2);
					questionsOrNull.bytecodes.push_back(question);
					responsesOrNull.bytecodes.push_back(response); 
				}
			}
		}
	}
	auto urls = conversationParseUrls(xhtmlFile);
	for(auto url : urls) {
		if(!listHasValue(questionsOrNull.signatures, url) && !listHasValue(noRobots, url)) {
			execvex("wget '" + url + "' -O" + xhtmlFile);
			questionsOrNull.signatures.push_back(url);
			questionsResponsesFromXhtml(questionsOrNull, responsesOrNull, xhtmlFile);
		}
	}
}
#ifdef BOOST_VERSION
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#endif /* BOOST_VERSION */
const std::vector<FilePath> conversationParseUrls(const FilePath &xhtmlFile) {
	const std::vector<FilePath> urls;
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
const FileBytecode conversationParseQuestion(const FilePath &xhtmlFile) {} /* TODO */
const std::vector<FileBytecode> conversationParseResponses(const FilePath &xhtmlFile) {} /* TODO */

const std::string conversationCnsProcess(const Cns &cns, const FileBytecode &bytecode) {
	return cns.processToString(bytecode);
}

void conversationCnsLoopProcess(const Cns &cns) {
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

/* To process fast (lag less,) use flags which auto-vectorizes/auto-parallelizes; To do `produceConversationCns` fast, use TensorFlow's `MapReduce`;
 * https://swudususuwu.substack.com/p/howto-run-devices-phones-laptops
 */
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ConversationCns_cxx */

