/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDES_cxx_VirusAnalysis_cxx
#define INCLUDES_cxx_VirusAnalysis_cxx
#include <vector> /* std::vector */
#include <string> /* std::string */
#include <tuple> /* std::tuple */
#include <algorithm> /* std::sort */
#include <utility> /* std::get */
#include "ClassSha2.hxx" /* Sha2 */
#include "ClassCns.hxx" /* Cns, CnsMode, posixExec */
#include "ClassResultList.hxx" /* listHas, ResultList, smallestUniqueSubstr */
#include "ClassPortableExecutable.hxx" /* PortableExecutable */
#include "VirusAnalysis.hxx" /* passList, abortList, *AnalyisCaches */
/* (Work-in-progress) virus analysis: uses hashes, signatures, static analysis, sandboxes, plus artificial CNS (central nervous systems) */
namespace Susuwu {
const bool virusAnalysisTestsThrows() {
	ResultList abortOrNull {
		.bytecodes {  /* Produce from an antivirus vendor's (such as VirusTotal.com's) infection databases */
			"infection",
			"infectedSW",
			"corruptedSW",
			""
		}
	};
	ResultList passOrNull {
		.bytecodes {  /* Produce from an antivirus vendor's (such as VirusTotal.com's) fresh-files databases */
			"",
			"SW",
			"SW",
			"newSW"
		}
	};
	produceAbortListSignatures(passList, abortList);
	produceAnalysisCns(passOrNull, abortOrNull, ResultList(), analysisCns);
	produceDisinfectionCns(passOrNull, abortOrNull, disinfectionCns);
	/* callbackHook("exec", */ [](const PortableExecutable &file) { /* TODO: OS-specific "hook"/"callback" for `exec()`/app-launches */
		switch(virusAnalysis(file)) {
		case virusAnalysisPass:
			return true; /* launch this */
		case virusAnalysisRequiresReview:
			submitSampleToHosts(file); /* manual review */
			return false;
		default:
			return false; /* abort */
		}
	} /* ) */ ;
	return true;
}
const VirusAnalysisResult virusAnalysis(const PortableExecutable &file) {
	const auto fileHash = Sha2(file.bytecode);
	for(decltype(virusAnalyses[0]) analysis : virusAnalyses) {
		switch(analysis(file, fileHash)) {
			case virusAnalysisPass:
				return virusAnalysisPass;
			case virusAnalysisRequiresReview:
				/*submitSampleToHosts(file);*/ /* TODO:? up to caller to do this? */
				return virusAnalysisRequiresReview;
			case virusAnalysisAbort:
				return virusAnalysisAbort;
			default: /* virusAnalysisContinue */
		}
	}
	return virusAnalysisPass;
}

/* Hash analysis */
const VirusAnalysisResult hashAnalysis(const PortableExecutable &file, const ResultListHash &fileHash) {
	try {
		const auto result = hashAnalysisCaches.at(fileHash);
		return result;
	} catch (...) {
		if(listHas(passList.hashes, fileHash)) {
			return hashAnalysisCaches[fileHash] = virusAnalysisPass;
		} else if(listHas(abortList.hashes, fileHash)) {
			return hashAnalysisCaches[fileHash] = virusAnalysisAbort;
		} else {
			return hashAnalysisCaches[fileHash] =  virusAnalysisContinue; /* continue to next tests */
		}
	}
}

/* Signatures analysis */
const VirusAnalysisResult signatureAnalysis(const PortableExecutable &file, const ResultListHash &fileHash) {
	try {
		const auto result = signatureAnalysisCaches.at(fileHash);
		return result;
	} catch (...) {
		for(decltype(abortList.signatures[0]) sig : abortList.signatures) {
#if PREFERENCE_IS_CSTR
		 	if(strstr(file.hex, sig)) { /* strstr uses text/hex; hex uses more space than binary, so you should use `memmem` or `std::search` with file.bytecode */
#else /* else !PREFERENCE_IS_CSTR */
			if(file.bytecode.end() != std::search(file.bytecode.begin(), file.bytecode.end(), sig.begin(), sig.end())) {
#endif /* PREFERENCE_IS_CSTR else */
				return signatureAnalysisCaches[fileHash] = virusAnalysisAbort;
		 	}
		}
		return signatureAnalysisCaches[fileHash] = virusAnalysisContinue;
	}
}

/* To produce virus signatures:
 * use passlists of all files that was reviewed that pass,
 * plus abortlists of all files that failed manual review, such lists as Virustotal has.
 * `produceAbortListsignatures()` is to produce the `abortList.signatures` list, with the smallest substrings unique to infected files;
 * is slow, requires huge database of executables, and is not for clients.
 */
void produceAbortListSignatures(const ResultList &passList, ResultList &abortList) {
	for(decltype(abortList.bytecodes[0]) file : abortList.bytecodes) {
		auto tuple = smallestUniqueSubstr(file, passList.bytecodes);
		abortList.signatures.push_back(ResultListSignature(std::get<0>(tuple), std::get<1>(tuple)));
	} /* The most simple signature is a substring, but some analyses use regexes. */
}
/* Comodo has a list of virus signatures to check against at https://www.comodo.com/home/internet-security/updates/vdp/database.php */

/* Static analysis */
const std::vector<std::string> importedFunctionsList(const PortableExecutable &file) {
	/* TODO; parse PortableExecutable (or ELF) .bytecode, return function imports */
}
/*
 * importedFunctionsList resources; “Portable Executable” for Windows ( https://learn.microsoft.com/en-us/windows/win32/debug/pe-format https://wikipedia.org/wiki/Portable_Executable ,
 * “Extended Linker Format” for most others such as UNIX/Linuxes ( https://wikipedia.org/wiki/Executable_and_Linkable_Format ),
 * shows how to analyse lists of libraries(.DLL's/.SO's) the SW uses,
 * plus what functions (new syscalls) the SW can goto through `jmp`/`call` instructions.
 *
 * "x86" instruction list for Intel/AMD ( https://wikipedia.org/wiki/x86 ),
 * "aarch64" instruction list for most smartphones/tablets ( https://wikipedia.org/wiki/aarch64 ),
 * shows how to analyse what OS functions the SW goes to without libraries (through `int`/`syscall`, old;  most new SW uses `jmp`/`call`.)
 * Plus, instructions lists show how to analyse what args the apps/SW pass to functions/syscalls (simple for constant args such as "push 0x2; call functions;",
 * but if registers/addresses as args such as "push eax; push [address]; call [address2];" must guess what is *"eax"/"[address]"/"[address2]", or use sandboxes.
 *
 * https://www.codeproject.com/Questions/338807/How-to-get-list-of-all-imported-functions-invoked shows how to analyse dynamic loads of functions (if do this, `syscallPotentialDangers[]` does not include `GetProcAddress()`.)
 */
const VirusAnalysisResult staticAnalysis(const PortableExecutable &file, const ResultListHash &fileHash) {
	try {
		const auto result = staticAnalysisCaches.at(fileHash);
		return result;
	} catch (...) {
		auto syscallsUsed = importedFunctionsList(file);
		typeof(syscallsUsed) syscallPotentialDangers = {
			"memopen", "fwrite", "socket", "GetProcAddress", "IsVmPresent"
		};
		std::sort(syscallPotentialDangers.begin(), syscallPotentialDangers.end());
		std::sort(syscallsUsed.begin(), syscallsUsed.end());
		if(listsIntersect(syscallPotentialDangers, syscallsUsed)) {
			return staticAnalysisCaches[fileHash] = virusAnalysisRequiresReview;
		}
		return staticAnalysisCaches[fileHash] = virusAnalysisContinue;
	}
}

/* Analysis sandbox */
const VirusAnalysisResult sandboxAnalysis(const PortableExecutable &file, const ResultListHash &fileHash) {
	try {
		const auto result = sandboxAnalysisCaches.at(fileHash);
		return result;
	} catch (...) {
		posixExec("/bin/cp", "-r '/usr/home/sandbox/' '/usr/home/sandbox.bak'"); /* or produce FS snapshot */
		posixExec("/bin/cp", "'" + file.path + "' '/usr/home/sandbox/'");
		posixExec("/bin/chroot", "'/usr/home/sandbox/' \"strace basename '" + file.path + "'\" >> strace.outputs");
		posixExec("/bin/mv/", "'/usr/home/sandbox/strace.outputs' '/tmp/strace.outputs'");
		posixExec("/bin/sh", "-c 'rm -r /usr/home/sandbox/ && mv /usr/home/sandbox.bak /usr/home/sandbox/'"); /* or restore FS snapshot */
		return sandboxAnalysisCaches[fileHash] = straceOutputsAnalysis("/tmp/strace.outputs");
	}
}
const VirusAnalysisResult straceOutputsAnalysis(const FilePath &straceDumpPath) {
	return virusAnalysisContinue;
}

/* Analysis CNS */
/* Replace `Cns` with the typedef of your CNS, such as `HSOM` or `apxr` */

/* To train (setup synapses) the CNS, is slow plus requires access to huge sample databases,
but the synapses use small resources (allow clients to do fast analysis.) */
void produceAnalysisCns(const ResultList &pass, const ResultList &abort,
const ResultList &unreviewed /* = ResultList(), WARNING! Possible danger to use unreviewed samples */,
Cns &cns /* = analysisCns */
) {
	std::vector<const std::tuple<const FileBytecode, float>> inputsToPass, inputsToUnreviewed, inputsToAbort;
	const size_t maxPassSize = maxOfSizes(pass.bytecodes);
	const size_t maxAbortSize = maxOfSizes(abort.bytecodes);
	cns.setInputMode(cnsModeString);
	cns.setOutputMode(cnsModeFloat);
	cns.setInputNeurons(maxPassSize > maxAbortSize ? maxPassSize : maxAbortSize);
	cns.setOutputNeurons(1);
	cns.setLayersOfNeurons(6666);
	cns.setNeuronsPerLayer(26666);
	for(decltype(pass.bytecodes[0]) bytecodes : pass.bytecodes) {
		inputsToPass.push_back({bytecodes, 1.0});
	}
	cns.setupSynapses(inputsToPass);
	if(unreviewed.bytecodes.size()) { /* WARNING! Possible danger to use unreviewed samples */
		for(decltype(pass.bytecodes[0]) bytecodes : unreviewed.bytecodes) {
			inputsToUnreviewed.push_back({bytecodes, 1 / 2});
		}
		cns.setupSynapses(inputsToUnreviewed);
	}
	for(decltype(abort.bytecodes[0]) bytecodes : abort.bytecodes) {
		inputsToAbort.push_back({bytecodes, 0.0});
	}
	cns.setupSynapses(inputsToAbort);
}
const float cnsAnalysisScore(const PortableExecutable &file, const Cns &cns /* = analysisCns */) {
	return cns.processToFloat(file.bytecode);
}
const VirusAnalysisResult cnsAnalysis_(const PortableExecutable &file, const ResultListHash &fileHash, const Cns &cns /* = analysisCns */) {
	try {
		const auto result = cnsAnalysisCaches.at(fileHash);
		return result;
	} catch (...) {
		return cnsAnalysisCaches[fileHash] = (bool)round(cnsAnalysisScore(file, cns)) ? virusAnalysisContinue : virusAnalysisRequiresReview;
	}
}
const VirusAnalysisResult cnsAnalysis(const PortableExecutable &file, const ResultListHash &fileHash) {
	return cnsAnalysis_(file, fileHash);
}

/* Disinfection CNS */

/* `abortOrNull` should map to `passOrNull` (`ResultList` is composed of `std::tuple`s, because just `produceDisinfectionCns()` requires file),
 * with `abortOrNull.bytecodes[x] = NULL` (or "\0") for new SW synthesis,
 * and `passOrNull.bytecodes[x] = NULL` (or "\0") if infected and CNS can not cleanse file.
 */

/* Uses more resources than `produceAnalysisCns()`, can restore infected SW to as-new SW */
void produceDisinfectionCns(
	const ResultList &passOrNull, /* Expects `resultList.bytecodes[x] = NULL` if does not pass */
	const ResultList &abortOrNull, /* Expects `resultList.bytecodes[x] = NULL` if does pass */
	Cns &cns /* = disinfectionCns */
) {
	std::vector<const std::tuple<const FileBytecode, const FileBytecode>> inputsToOutputs;
	cns.setInputMode(cnsModeString);
	cns.setOutputMode(cnsModeString);
	cns.setInputNeurons(maxOfSizes(passOrNull.bytecodes));
	cns.setOutputNeurons(maxOfSizes(abortOrNull.bytecodes));
	cns.setLayersOfNeurons(6666);
	cns.setNeuronsPerLayer(26666);
	assert(passOrNull.bytecodes.size() == abortOrNull.bytecodes.size());
	for(int x = 0; passOrNull.bytecodes.size() > x; ++x) {
		inputsToOutputs.push_back({abortOrNull.bytecodes[x], passOrNull.bytecodes[x]});
	}
	cns.setupSynapses(inputsToOutputs);
}

/* Uses more resources than `cnsAnalysis()` */
const FileBytecode cnsDisinfection(const PortableExecutable &file, const Cns &cns /* = disinfectionCns */) {
	return cns.processToString(file.bytecode);
}

/* Related to this:
 * `cnsDisinfection` is close to conversation bots (such as "ChatGPT 4.0" or "Claude-3 Opus",) "HSOM" (the simple Python artificial CNS) is enough to do this;
 * #include "ConversationCns.cxx"
 *
 * To process fast (lag less,) use flags which auto-vectorizes/auto-parallelizes; To do `produce*Cns` fast, use TensorFlow's `MapReduce`;
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
#endif /* ndef INCLUDES_cxx_VirusAnalysis_cxx */

