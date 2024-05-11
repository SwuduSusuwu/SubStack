/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDE_GUARD_c___VirusAnalysis_h__
#define INCLUDE_GUARD_c___VirusAnalysis_h__
#include <iostream> /* std::string */
#include "ClassCns.h" /* Cns, CnsMode */
#include "ClassResultList.h" /* ResultList, smallestUniqueSubstr */
#include "ClassPortableExecutable.h" /* Not included */
/* (Work-in-progress) virus analysis (can use hashes, signatures, functional analysis, sandboxes, and artificial CNS (central nervous systems */
namespace Susuwu {
ResultList passList, abortList; /* Stored on disk, all clients use clones of this */
ResultList localPassList; /* Temporary local caches */
const bool hashAnalysisPass(const PortableExecutable *); /* True if passes hash analysis */
const bool signatureAnalysisPass(const PortableExecutable *); /* True if passes signature analysis */
const bool hashPlusSignatureAnalysisPass(const PortableExecutable *); /* True if passes hash+signature analysis */
const bool functionalAnalysisPass(const PortableExecutable *); /* To skip, define as `return true;` */
const bool sandboxPass(const PortableExecutable *); /* To skip, define as `return true;` */
const bool straceOutputsPass(const char *path); /* Unimplemented, `strace()` resources have clues how to do this */
const float cnsAnalysis(const Cns *cns, const std::string &bytes); /* To skip, define as `return 1;` */
const bool cnsPass(const Cns *cns, const std::string &bytes); /* = `(bool)round(cnsAnalysis(cns, bytes)` */
vector<char> cnsDisinfection(const Cns *cns, const std::string &bytes); /* This can undo infection from bytecodes (restores to fresh executables) */

/* To produce virus signatures:
 * use passlists of all files that was reviewed that pass,
 * plus abortlists of all files that failed manual review, such lists as Virustotal has.
 * `signatureSynthesis()` is to produce the `abortList.signatures` list, with the smallest substrings unique to infected files;
 * is slow, requires huge database of executables, and is not for clients.
 */
void signatureSynthesis(ResultList *passList, ResultList *abortList);
/* Comodo has a list of virus signatures to check against at https://www.comodo.com/home/internet-security/updates/vdp/database.php */

/* Functional analysis */
const std::vector<std::string> importedFunctionsList(PortableExecutable *);
const bool functionalAnalysisPass(PortableExecutable *);

/* Analysis sandbox */
const bool sandboxPass(const PortableExecutable *);

/* Analysis CNS */
/* To train (setup synapses) the CNS, is slow plus requires access to huge sample databases,
but the synapses use small resources (allow clients to do fast analysis.) */
void setupAnalysisCns(Cns *cns, const ResultList *pass, const ResultList *abort,
const ResultList *unreviewed = NULL /* WARNING! Possible danger to use unreviewed samples */
);
const float cnsAnalysis(const Cns *cns, const std::string &bytes);
const bool cnsPass(const Cns *cns, const std::string &bytes);

/* Disinfection CNS */
/* `abortOrNull` should map to `passOrNull` (`ResultList` is composed of `std::tuple`s, because just `setupDisinfectionCns()` requires this),
 * with `abortOrNull->bytes[x] = NULL` (or "\0") for new SW synthesis,
 * and `passOrNull->bytes[x] = NULL` (or "\0") if infected and CNS can not cleanse this.
 */
ResultList abortOrNull;
ResultList passOrNull;

/* Uses more resources than `setupAnalysisCns()` */
void setupDisinfectionCns(Cns *cns,
	const ResultList *passOrNull, /* Expects `resultList->bytes[x] = NULL` if does not pass */
	const ResultList *abortOrNull /* Expects `resultList->bytes[x] = NULL` if does pass */
);

/* Uses more resources than `cnsAnalysis()` */
const std::string cnsDisinfection(const Cns *cns, const std::string &bytes);

/* Related to this:
 * `cnsDisinfection` is close to conversation bots (such as "ChatGPT 4.0" or "Claude-3 Opus",) "HSOM" (the simple Python artificial CNS) is enough to do this;
 * #include "ConversationCns.c++"
 *
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
#endif /* ndef INCLUDE_GUARD_c___VirusAnalysis_h__ */

