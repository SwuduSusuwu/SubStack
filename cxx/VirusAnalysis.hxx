/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#pragma once
#ifndef INCLUDES_cxx_VirusAnalysis_hxx
#define INCLUDES_cxx_VirusAnalysis_hxx
#include <map> /* std::map */
#include <vector> /* std::vector */
#include <string> /* std::string */
#include "ClassCns.hxx" /* Cns, CnsMode */
#include "ClassResultList.hxx" /* ResultList, smallestUniqueSubstr */
#include "ClassPortableExecutable.hxx" /* PortableExecutable FilePath FileBytecode */
/* (Work-in-progress) virus analysis (can use hashes, signatures, functional analysis, sandboxes, and artificial CNS (central nervous systems */
namespace Susuwu {
typedef enum VirusAnalysisResult {
	virusAnalysisAbort = (short)false, /* do not launch */
	virusAnalysisPass = (short)true, /* launch this (sample passes) */
	virusAnalysisRequiresReview, /* submit to hosts to do analysis */
	virusAnalysisContinue /* continue to next tests (is normal; most analyses can not prove that samples pass) */
} VirusAnalysisResult;
ResultList passList, abortList; /* Stored on disk, all clients use clones of this */
std::map<ResultListHash, VirusAnalysisResult> hashAnalysisCaches, signatureAnalysisCaches, staticAnalysisCaches, sandboxAnalysisCaches, cnsAnalysisCaches; /* Temporary local caches */
Cns analysisCns, disinfectionCns;
/* if (with example inputs) these functions (`produceAbortListSignatures()`, `produceAnalysisCns()`, `produceDisinfectionCns()`) pass, `return true;`
 * @pre @code analysisCns.hasImplementation() && disinfectionCns.hasImplementation() @endcode */
const bool virusAnalysisTestsThrows();
const bool virusAnalysisTests() {try {return virusAnalysisTestsThrows();} catch(...) {return false;}}

const VirusAnalysisResult submitSampleToHosts(const PortableExecutable &) {return virusAnalysisRequiresReview;} /* TODO: requires compatible hosts to upload to */
const VirusAnalysisResult virusAnalysis(const PortableExecutable &); /* hashAnalysis + signatureAnalysis + staticAnalysis + sandboxAnalysis + cnsAnalysis */

const VirusAnalysisResult hashAnalysis(const PortableExecutable &, const ResultListHash &); /* `if(abortList[sample]) {return Abort;} if(passList[sample] {return Pass;} return Continue;` */

/* To produce virus signatures:
 * use passlists (of files reviewed which pass),
 * plus abortlists (of files which failed), such lists as Virustotal has.
 * `produceAbortListSignatures()` is to produce the `abortList.signatures` list, with the smallest substrings unique to infected files; is slow, requires huge database of executables; just hosts should produce this.
 * For clients: Comodo has lists of virus signatures to check against at https://www.comodo.com/home/internet-security/updates/vdp/database.php
 * @throw std::bad_alloc
 * @pre @code passList.bytecodes.size() && abortList.bytecodes.size() && !listsIntersect(passList.bytecodes, abortList.bytecodes) @endcode
 * @post @code abortList.signatures.size() @endcode */
void produceAbortListSignatures(const ResultList &passList, ResultList &abortList);
 /* `if(intersection(sample.bytecode, abortList.signatures)) {return VirusAnalysisRequiresReview;} return VirusAnalysisContinue;` 
	* @pre @code abortList.signatures.size() @endcode */
const VirusAnalysisResult signatureAnalysis(const PortableExecutable &sample, const ResultListHash &abortList);

/* Static analysis */
/* @throw bad_alloc */
const std::vector<std::string> importedFunctionsList(const PortableExecutable &);
const VirusAnalysisResult staticAnalysis(const PortableExecutable &, const ResultListHash &); /* if(intersection(importedFunctionsList(sample), dangerFunctionsList)) {return RequiresReview;} return Continue;` */

/* Analysis sandbox */
const VirusAnalysisResult sandboxAnalysis(const PortableExecutable &, const ResultListHash &); /* `chroot(strace(sample)) >> outputs; return straceOutputsAnalysis(outputs);` */
const VirusAnalysisResult straceOutputsAnalysis(const FilePath &straceDumpPath); /* TODO: `if(intersection(outputs, straceDangers)) {return RequiresReview;} return Continue; */

/* Analysis CNS */
/* To train (setup synapses) the CNS, is slow plus requires access to huge sample databases,
but the synapses use small resources (allow clients to do fast analysis.)
 * @pre @code cns.hasImplementation() && pass.bytecodes.size() && abort.bytecodes.size() @endcode
 * @post @code cns.isInitialized() @endcode */
void produceAnalysisCns(const ResultList &pass, const ResultList &abort,
	const ResultList &unreviewed = ResultList() /* WARNING! Possible danger to use unreviewed samples */,
	Cns &cns = analysisCns
);
/* If bytecode resembles `abortList`, `return 0;`. If undecidable (resembles `unreviewedList`), `return 1 / 2`. If resembles passList, `return 1;`
 * @pre @code cns.isInitialized() @endcode */
const float cnsAnalysisScore_(const PortableExecutable &, const Cns &cns = analysisCns);
/* `return (bool)round(cnsAnalysisScore(file, fileHash))`
 * @pre @code cns.isInitialized() @endcode */
const VirusAnalysisResult cnsAnalysis_(const PortableExecutable &file, const ResultListHash &fileHash, const Cns &cns = analysisCns);
const VirusAnalysisResult cnsAnalysis(const PortableExecutable &file, const ResultListHash &fileHash);

/* Setup disinfection CNS, uses more resources than `produceAnalysisCns()` */
/* `abortOrNull` should map to `passOrNull` (`ResultList` is composed of `std::tuple`s, because just `produceDisinfectionCns()` requires this),
 * with `abortOrNull->bytecodes[x] = NULL` (or "\0") for new SW synthesis,
 * and `passOrNull->bytecodes[x] = NULL` (or "\0") if infected and CNS can not cleanse this.
 * @pre @code cns.hasImplementation() @endcode
 * @post @code cns.isInitialized() @encode
 */
void produceDisinfectionCns(
	const ResultList &passOrNull, /* Expects `resultList->bytecodes[x] = NULL` if does not pass */
	const ResultList &abortOrNull, /* Expects `resultList->bytecodes[x] = NULL` if does pass */
	Cns &cns = disinfectionCns
);

/* Uses more resources than `cnsAnalysis()`, can undo infection from bytecodes (restore to fresh SW) 
 * @pre @code cns.isInitialized() @endcode */
const std::string cnsDisinfection(const PortableExecutable &, const Cns &cns = disinfectionCns);

/* Related to this:
 * `cnsDisinfection` is close to conversation bots (such as "ChatGPT 4.0" or "Claude-3 Opus",) "HSOM" (the simple Python artificial CNS) is enough to do this;
 * #include "ConversationCns.cxx"
 *
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
#endif /* ndef INCLUDES_cxx_VirusAnalysis_hxx */

