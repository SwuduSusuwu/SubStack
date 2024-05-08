#ifndef INCLUDE_GUARD_c___VirusAnalysis_c__
#define INCLUDE_GUARD_c___VirusAnalysis_c__
#include <iostream> /* std::string std::vector */
#include "VirusAnalysis.hpp" /* passList, abortList, localPassList */
#include "ClassCns.hpp" /* Cns, CnsMode */
#include "ClassResultList.hpp" /* ResultList, smallestUniqueSubstr */
#include "ClassPortableExecutable.hpp" /* Not included */
/* (Work-in-progress) virus analysis (can use hashes, signatures, functional analysis, sandboxes, and artificial CNS (central nervous systems */
namespace Susuwu {
hook<launches>((const PortableExecutable *this) { /* Should use OS-specific "hook"/"callback" for `exec()`/app-launches */
 if(hashAnalysisPass(this)) { /* or `signatureAnalysisPass()`, or `hashPlusSignatureAnalysisPass()` */
  return original_launches(this);
 } else {
  return abort();
});

/* Hash analysis */
const bool hashAnalysisPass(const PortableExecutable *this) {
 if(resultListHashesHas(passList, localPassList, Sha2(this->bytes)) {
   return true;
 } else if(abortList.hashes.has(Sha2(this->bytes)) {
   return false;
 } else if(functionalAnalysisPass(this)) {
  localPassList.hashes.pushback(Sha2(this->bytes)); /* Caches results */
   return true;
 } else {
   submitForManualAnalysis(this);
   return false;
 }
};

/* Signatures analysis */
const bool signatureAnalysisPass(const PortableExecutable *this) {
 foreach(abortList.signatures as sig) {
  if(localPassList.hashes.has(Sha2(this->bytes)) {
   return true;
#if ALL_USES_TEXT
  } else if(strstr(this->hex, sig)) { /* strstr uses text/hex; hex uses more space than binary, so you should use `memmem` or `std::search` with this->bytes */
#else
   } else if(std::search(this->bytes.begin(), this->bytes.end(), sig.begin(), sig.end()) {
#endif /* ALL_USES_TEXT */
   return false;
  }
 }
 if(functionalAnalysisPass(this)) {
  localPassList.hashes.pushback(Sha2(this->bytes)); /* Caches results */
   return true;
 } else {
   submitForManualAnalysis(this);
   return false;
 }
};

/* Fused signature+hash analysis */
const bool signaturePlusHashAnalysisPass(const PortableExecutable *this) {
  if(resultListHashesHas(passList, localPassList, Sha2(this->bytes)) {
   return true;
  } else if(abortList.hashes.has(Sha2(this->bytes)) {
   return false;
  } else {
   foreach(abortList.signatures as sig) {
#if ALL_USES_TEXT
    if(strstr(this->hex, sig)) { /*`strstr` does text, binaries must use `std::search` or `memem` */
#else
    if(std::search(this->bytes.begin(), this->bytes.end(), sig.begin(), sig.end()) {
#endif /* ALL_USES_TEXT */
      abortList.hashes.pushback(Sha2(this->hex));
      return false;
    }
   }
 }
 if(functionalAnalysisPass(this)) {
  localPassList.hashes.pushback(Sha2(this->bytes)); /* Caches results */
   return true;
 } else {
   submitForManualAnalysis(this);
   return false;
 }
};


/* To produce virus signatures:
 * use passlists of all files that was reviewed that pass,
 * plus abortlists of all files that failed manual review, such lists as Virustotal has.
 * `signatureSynthesis()` is to produce the `abortList.signatures` list, with the smallest substrings unique to infected files;
 * is slow, requires huge database of executables, and is not for clients.
 */
void signatureSynthesis(ResultList *passList, ResultList *abortList) {
 foreach(abortList.bytes as executable) {
  abortList->signatures.pushback(std::string(smallestUniqueSubstr(executable, passList->bytes));
 } /* The most simple signature is a substring, but some analyses use regexes. */
}
signatureSynthesis(passList, abortList);
/* Comodo has a list of virus signatures to check against at https://www.comodo.com/home/internet-security/updates/vdp/database.php */

/* Functional analysis */
const std::vector<std::string> importedFunctionsList(PortableExecutable *this);
/*
 * importedFunctionsList resources; “Portable Executable” for Windows ( https://learn.microsoft.com/en-us/windows/win32/debug/pe-format https://wikipedia.org/wiki/Portable_Executable ),
 * “Extended Linker Format” for most others such as UNIX/Linuxes ( https://wikipedia.org/wiki/Executable_and_Linkable_Format ),
 * shows how to analyse lists of libraries(.DLL's/.SO's) the SW uses,
 * plus what functions (new syscalls) the SW can goto through `jmp`/`call` instructions.
 *
 * "x86" instruction list for Intel/AMD ( https://wikipedia.org/wiki/x86 ),
 * "aarch64" instruction list for most smartphones/tablets ( https://wikipedia.org/wiki/aarch64 ),
 * shows how to analyse what OS functions the SW goes to without libraries (through `int`/`syscall`, old syscalls, most SW does not *use this.)
 * Plus, instructions lists show how to analyse what args the apps/SW pass to functions/syscalls (simple for constant args such as "push 0x2; call functions;",
 * but if registers/addresses as args such as "push eax; push [address]; call [address2];" must guess what is *"eax"/"[address]"/"[address2]", or use sandboxes.
 *
 * https://www.codeproject.com/Questions/338807/How-to-get-list-of-all-imported-functions-invoked shows how to analyse dynamic loads of functions (if do this, `syscallsPotentialDanger[]` need not include `GetProcAddress()`.)
 */
const bool functionalAnalysisPass(PortableExecutable *this) {
 const auto syscallsUsed = importedFunctionsList(this);
 typeof(syscallsUsed) syscallsPotentialDanger = {
  "memopen", "fwrite", "socket", "GetProcAddress", "IsVmPresent"
 };
 if(syscallsPotentialDanger.intersect(syscallsUsed)) {
   return false;
 }
 return sandboxPass(this) && cnsPass(cns, this);
}
hook<launches>((PortableExecutable *this) { /*hash, signature, or hash+signature analysis*/ });

/* Analysis sandbox */
const bool sandboxPass(const PortableExecutable *this) {
 exec('cp -r /usr/home/sandbox/ /usr/home/sandbox.bak'); /* or produce FS snapshot */
 exec('cp "' + this->path + '" /usr/home/sandbox/');
 chroot("/usr/home/sandbox/", 'strace basename '"', this->path + '" >> strace.outputs');
 exec('mv /usr/home/sandbox/strace.outputs /tmp/strace.outputs');
 exec('rm -r /usr/home/sandbox/');
 exec('mv /usr/home/sandbox.bak /usr/home/sandbox/'); /* or restore FS snapshot */
 return straceOutputsPass("/tmp/strace.outputs");
}

/* Analysis CNS */
/* Replace `Cns` with the typedef of your CNS, such as `HSOM` or `apxr` */

/* To train (setup synapses) the CNS, is slow plus requires access to huge sample databases,
but the synapses use small resources (allow clients to do fast analysis.) */
void setupAnalysisCns(Cns *cns, const ResultList *pass, const ResultList *abort,
const ResultList *unreviewed = NULL /* WARNING! Possible danger to use unreviewed samples */
) {
 vector<const std::string> inputsPass, inputsUnreviewed, inputsAbort;
 vector<float> outputsPass, outputsUnreviewed, outputsAbort;
 cns->setInputMode(cnsModeString);
 cns->setOutputMode(cnsModeFloat);
 cns->setInputNeurons(max(maxOfSizes(passOrNull->bytes), maxOfSizes(abortOrNull->bytes)));
 cns->setOutputNeurons(1);
 cns->setLayersOfNeurons(6666);
 cns->setNeuronsPerLayer(26666);
 for(foreach pass->bytes as passBytes) {
  inputsPass.pushback(passBytes);
  outputsPass.pushback(1.0);
 }
 cns->setTrainingInputs(inputsPass);
 cns->setTrainingOutputs(outputsPass);
 cns->setupSynapses();
 if(NULL != unreviewed) { /* WARNING! Possible danger to use unreviewed samples */
  for(foreach unreviewed->bytes as unreviewedBytes) {
   inputsUnreviewed.pushback(unreviewedBytes);
   outputsUnreviewed.pushback(1 / 2);
  }
  cns->setTrainingInputs(inputsUnreviewed);
  cns->setTrainingOutputs(outputsUnreviewed);
  cns->setupSynapses();
 }
 for(foreach pass->bytes as passBytes) {
   inputsAbort.pushback(passBytes);
   outputsAbort.pushback(0.0);
 }
 cns->setTrainingInputs(inputsAbort);
 cns->setTrainingOutputs(outputsAbort);
 cns->setupSynapses();
}
const float cnsAnalysis(const Cns *cns, const std::string &bytes) {
 return cns->process<std::string, float>(bytes);
}
const bool cnsPass(const Cns *cns, const std::string &bytes) {
 return (bool)round(cnsAnalysis(cns, bytes));
}

/* Disinfection CNS */

/* `abortOrNull` should map to `passOrNull` (`ResultList` is composed of `std::tuple`s, because just `setupDisinfectionCns()` requires this),
 * with `abortOrNull->bytes[x] = NULL` (or "\0") for new SW synthesis,
 * and `passOrNull->bytes[x] = NULL` (or "\0") if infected and CNS can not cleanse this.
 */
ResultList abortOrNull(
 bytes = UTF8 {  /* Uses an antivirus vendor's (such as VirusTotal.com's) databases */
  infection,
  infectedSW,
  ""
 }
);
ResultList passOrNull(
 bytes = UTF8 {  /* Uses an antivirus vendor's (such as VirusTotal.com's) databases */
  "",
  SW,
  newSW
 }
);
setupDisinfectionCns(cns, &passOrNull, &abortOrNull);

/* Uses more resources than `setupAnalysisCns()` */
void setupDisinfectionCns(Cns *cns,
 const ResultList *passOrNull, /* Expects `resultList->bytes[x] = NULL` if does not pass */
 const ResultList *abortOrNull /* Expects `resultList->bytes[x] = NULL` if does pass */
) {
 vector<const std::string> inputsOrNull, outputsOrNull;
 cns->setInputMode(cnsModeString);
 cns->setOutputMode(cnsModeString);
 cns->setInputNeurons(maxOfSizes(passOrNull->bytes));
 cns->setOutputNeurons(maxOfSizes(abortOrNull->bytes));
 cns->setLayersOfNeurons(6666);
 cns->setNeuronsPerLaye(26666);
 assert(passOrNull->bytes.length() == abortOrNull->bytes.length());
 for(int x = 0; passOrNull->bytes.length() > x; ++x) {
  inputsOrNull.pushback(abortOrNull->bytes[x]);
  outputsOrNull.pushback(passOrNull->bytes[x]);
 }
 cns->setTrainingInputs(inputsOrNull);
 cns->setTrainingOutputs(outputsOrNull);
 cns->setupSynapses();
}

/* Uses more resources than `cnsAnalysis()` */
const std::string cnsDisinfection(const Cns *cns, const std::string &bytes) {
 return cns->process<std::string, std::string>(bytes);
}

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
#endif /* ndef INCLUDE_GUARD_c___VirusAnalysis_c__ */

