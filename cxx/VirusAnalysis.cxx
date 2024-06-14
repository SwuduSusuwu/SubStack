/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#ifndef INCLUDES_cxx_VirusAnalysis_cxx
#define INCLUDES_cxx_VirusAnalysis_cxx
#include <fstream> /* std::ifstream */
#include <vector> /* std::vector */
#include <string> /* std::string */
#include <tuple> /* std::tuple */
#include <algorithm> /* std::sort */
#include <utility> /* std::get */
#include "ClassSha2.hxx" /* Sha2 */
#include "ClassCns.hxx" /* Cns, CnsMode, posixExec */
#include "ClassResultList.hxx" /* ResultList, listMaxSize, listHasValue, ResultList, listProduceUniqueSubstr, listOfSubstrHasMatch */
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
	for(auto analysis : virusAnalyses) {
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

const VirusAnalysisResult hashAnalysis(const PortableExecutable &file, const ResultListHash &fileHash) {
	try {
		const auto result = hashAnalysisCaches.at(fileHash);
		return result;
	} catch (...) {
		if(listHasValue(passList.hashes, fileHash)) {
			return hashAnalysisCaches[fileHash] = virusAnalysisPass;
		} else if(listHasValue(abortList.hashes, fileHash)) {
			return hashAnalysisCaches[fileHash] = virusAnalysisAbort;
		} else {
			return hashAnalysisCaches[fileHash] =  virusAnalysisContinue; /* continue to next tests */
		}
	}
}

const VirusAnalysisResult signatureAnalysis(const PortableExecutable &file, const ResultListHash &fileHash) {
	try {
		const auto result = signatureAnalysisCaches.at(fileHash);
		return result;
	} catch (...) {
		if(listOfSubstrHasMatch(abortList.signatures, file.bytecode)) {
			return signatureAnalysisCaches[fileHash] = virusAnalysisAbort;
		}
		return signatureAnalysisCaches[fileHash] = virusAnalysisContinue;
	}
}

void produceAbortListSignatures(const ResultList &passList, ResultList &abortList) {
	abortList.signatures.reserve(abortList.bytecodes.size());
	for(auto file : abortList.bytecodes) {
		auto tuple = listProduceUniqueSubstr(passList.bytecodes, file);
		abortList.signatures.push_back(ResultListSignature(std::get<0>(tuple), std::get<1>(tuple)));
	} /* The most simple signature is a substring, but some analyses use regexes. */
}

const std::vector<std::string> importedFunctionsList(const PortableExecutable &file) {
/* TODO
 * Resources; “Portable Executable” for Windows ( https://learn.microsoft.com/en-us/windows/win32/debug/pe-format https://wikipedia.org/wiki/Portable_Executable ,
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
}

const VirusAnalysisResult staticAnalysis(const PortableExecutable &file, const ResultListHash &fileHash) {
	try {
		const auto result = staticAnalysisCaches.at(fileHash);
		return result;
	} catch (...) {
		auto syscallsUsed = importedFunctionsList(file);
		std::sort(syscallPotentialDangers.begin(), syscallPotentialDangers.end());
		std::sort(syscallsUsed.begin(), syscallsUsed.end());
		if(listsIntersect(syscallPotentialDangers, syscallsUsed)) {
			return staticAnalysisCaches[fileHash] = virusAnalysisRequiresReview;
		}
		return staticAnalysisCaches[fileHash] = virusAnalysisContinue;
	}
}

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
		auto straceDump = std::ifstream(straceDumpPath);
		std::vector<std::string> straceOutputs /*= explodeToList(straceDump, "\n")*/;
		for(std::string straceOutput; std::getline(straceDump, straceOutput); ) {
			straceOutputs.push_back(straceOutput);
		}
		std::sort(stracePotentialDangers.begin(), stracePotentialDangers.end());
		std::sort(straceOutputs.begin(), straceOutputs.end());
		if(listsIntersect(stracePotentialDangers, straceOutputs)) { /* Todo: regex */
			return virusAnalysisRequiresReview;
		}
	return virusAnalysisContinue;
}

void produceAnalysisCns(const ResultList &pass, const ResultList &abort,
const ResultList &unreviewed /* = ResultList(), WARNING! Possible danger to use unreviewed samples */,
Cns &cns /* = analysisCns */
) {
	std::vector<const std::tuple<const FileBytecode, float>> inputsToOutputs;
	const size_t maxPassSize = listMaxSize(pass.bytecodes);
	const size_t maxAbortSize = listMaxSize(abort.bytecodes);
	cns.setInputMode(cnsModeString);
	cns.setOutputMode(cnsModeFloat);
	cns.setInputNeurons(maxPassSize > maxAbortSize ? maxPassSize : maxAbortSize);
	cns.setOutputNeurons(1);
	cns.setLayersOfNeurons(6666);
	cns.setNeuronsPerLayer(26666);
	inputsToOutputs.reserve(pass.bytecodes.size());
	for(auto bytecodes : pass.bytecodes) {
		inputsToOutputs.push_back({bytecodes, 1.0});
	}
	cns.setupSynapses(inputsToOutputs);
	inputsToOutputs.clear();
	if(unreviewed.bytecodes.size()) { /* WARNING! Possible danger to use unreviewed samples */
		inputsToOutputs.reserve(unreviewed.bytecodes.size());
		for(auto bytecodes : unreviewed.bytecodes) {
			inputsToOutputs.push_back({bytecodes, 1 / 2});
		}
		cns.setupSynapses(inputsToOutputs);
		inputsToOutputs.clear();
	}
	inputsToOutputs.reserve(abort.bytecodes.size());
	for(auto bytecodes : abort.bytecodes) {
		inputsToOutputs.push_back({bytecodes, 0.0});
	}
	cns.setupSynapses(inputsToOutputs);
	inputsToOutputs.clear();
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

void produceDisinfectionCns(const ResultList &passOrNull, const ResultList &abortOrNull, Cns &cns /* = disinfectionCns */) {
	std::vector<const std::tuple<const FileBytecode, const FileBytecode>> inputsToOutputs;
	cns.setInputMode(cnsModeString);
	cns.setOutputMode(cnsModeString);
	cns.setInputNeurons(listMaxSize(passOrNull.bytecodes));
	cns.setOutputNeurons(listMaxSize(abortOrNull.bytecodes));
	cns.setLayersOfNeurons(6666);
	cns.setNeuronsPerLayer(26666);
	assert(passOrNull.bytecodes.size() == abortOrNull.bytecodes.size());
	inputsToOutputs.reserve(passOrNull.bytecodes.size());
	for(int x = 0; passOrNull.bytecodes.size() > x; ++x) {
		inputsToOutputs.push_back({abortOrNull.bytecodes[x], passOrNull.bytecodes[x]});
	}
	cns.setupSynapses(inputsToOutputs);
}

const FileBytecode cnsDisinfection(const PortableExecutable &file, const Cns &cns /* = disinfectionCns */) {
	return cns.processToString(file.bytecode);
}

/* To process fast (lag less,) use flags which auto-vectorizes/auto-parallelizes; To do `produce*Cns` fast, use TensorFlow's `MapReduce`;
 * https://swudususuwu.substack.com/p/howto-run-devices-phones-laptops
 */
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_VirusAnalysis_cxx */

