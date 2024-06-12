**Virus analysis tools should use local static analysis + sandboxes + artificial CNS (central nervous systems) to secure us**
_[This post](https://swudususuwu.substack.com/p/howto-produce-better-virus-scanners) allows all uses._

Static analysis + sandbox + CNS = 1 second (approx) analysis of **new executables** (protects all app launches,) but _caches_ reduce this to **less than 1ms** (just cost to lookup `ResultList::hashes`, which is `std::unordered_set<decltype(Sha2(const FileBytecode &))>`; a hashmap of hashes).

`Licenses: allows all uses ("Creative Commons"/"Apache 2")`
For the most new sources, use apps such as [iSH](https://apps.apple.com/us/app/ish-shell/id1436902243) (for **iOS**) or [Termux](https://play.google.com/store/apps/details?id=com.termux) (for **Android OS**) to run this:
`git clone https://github.com/SwuduSusuwu/SubStack.git && cd Substack`
`less` [cxx/ClassPortableExecutable.hxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/ClassPortableExecutable.hxx)
```
typedef std::string FilePath; /* TODO: `std::char_traits<unsigned char>`, `std::basic_string<unsigned char>("string literal")` */
typedef FilePath FileBytecode; /* Uses `std::string` for bytecode (versus `std::vector`) because:
 * "If you are going to use the data in a string like fashon then you should opt for std::string as using a std::vector may confuse subsequent maintainers. If on the other hand most of the data manipulation looks like plain maths or vector like then a std::vector is more appropriate." -- https://stackoverflow.com/a/1556294/24473928
*/
typedef FilePath FileHash; /* TODO: `std::unordered_set<std::basic_string<unsigned char>>` */
typedef class PortableExecutable {
/* TODO: Unimplemented (work-in-progress) just to allow `cxx/VirusAnalysis.cxx` to compile. You should replace with official implementation of this. */
public:
	FilePath path; /* Suchas "C:\Program.exe" or "/usr/bin/library.so" */
	FileBytecode bytecode; /* compiled programs; bytecode */
	std::string hex; /* `hexdump(path)`, hexadecimal, for C string functions */
} PortableExecutable;
```
`less` [cxx/ClassSha2.cxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/ClassSha2.cxx)
```
/* Uses https://www.rfc-editor.org/rfc/rfc6234#section-8.2.2 */
/* const */ FileHash /* 256 bits, not null-terminated */ Sha2(const FileBytecode &bytecode) {
	FileHash result;
	SHA256Context context;
	result.reserve(SHA256HashSize);
	SHA256Reset(&context);
	SHA256Input(&context, reinterpret_cast<const unsigned char *>(bytecode.c_str()), bytecode.size());
	SHA256Result(&context, const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(result.c_str())));
	return result;
}
```
`less` [cxx/ClassResultList.hxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/ClassResultList.hxx)
```
typedef FileHash ResultListHash;
typedef FileBytecode ResultListBytecode; /* Should have structure of FileBytecode, but is not just for files, can use for UTF8/webpages, so have a new type for this */
typedef FilePath ResultListSignature; /* TODO: `typedef ResultListBytecode ResultListSignature; ResultListSignature("string literal");` */
typedef struct ResultList { /* Lists of files (or pages) */
	std::unordered_set<ResultListHash> hashes; /* Unique checksums of files (or pages), to avoid duplicates, plus to do fast checks for existance */
	std::vector<ResultListSignature> signatures; /* Smallest substrings (or regexes, or Universal Resource Locator) unique to this, has uses close to `hashes` but can match if files have small differences */
	std::vector<ResultListBytecode> bytecodes; /* Whole files (or webpages); uses lots of space, just populate this for signature synthesis (or training CNS). */
} ResultList;

template<class List>
const size_t maxOfSizes(const List &list) {
#if PREFERENCE_IS_CSTR
	size_t max = 0;
	for(auto it = &list[0]; list.cend() != it; ++it) { const size_t temp = strlen(*it); if(temp > max) {max = temp;}}
	return max; /* WARNING! `strlen()` just does UTF8-strings/hex-strings; if binary, must use `it->size()` */
#else /* else !PREFERENCE_IS_CSTR */
	auto it = std::max_element(list.cbegin(), list.cend(), [](const auto &s, const auto &x) { return s.size() < x.size(); });
	return it->size();
#endif /* PREFERENCE_IS_CSTR else */
}

/* @pre @code std::is_sorted(list.cbegin(), list.cend()) && std::is_sorted(list2.cbegin(), list2.cend()) @endcode */
template<class List>
const List listIntersections(const List &list, const List &list2) {
	List intersections;
	std::set_intersection(list.cbegin(), list.cend(), list2.cbegin(), list2.cend(), std::back_inserter(intersections));
	return intersections;
}
template<class List>
const bool listsIntersect(const List &list, const List &list2) {
	return listIntersections(list, list2).size();
}

template<class List>
auto listFindValue(const List &list, const typename List::value_type &x) {
	return std::find(list.cbegin(), list.cend(), x);
}
template<class List>
const bool listHasValue(const List &list, const typename List::value_type &x) {
	return list.cend() != listFindValue(list, x);
}
template<class List>
/* @pre @code s < x @endcode */
auto listFindSubstr(const List &list, typename List::value_type::const_iterator s, typename List::value_type::const_iterator x) {
	for(auto value : list) {
		auto result = std::search(value.cbegin(), value.cend(), s, x, [](char ch1, char ch2) { return ch1 == ch2; });
		if(value.cend() != result) {
			return result;
		}
	}
	return list.back().cend();
}
template<class List>
/* @pre @code s < x @endcode */
const bool listHasSubstr(const List &list, typename List::value_type::const_iterator s, typename List::value_type::const_iterator x) {
	return list.back().cend() != listFindSubstr(list, s, x);
}
template<class List>
/* Usage: resultList.signatures.push_back({listProduceUniqueSubstr(resultList.bytecodes, bytecode)); */
const std::tuple<typename List::value_type::const_iterator, typename List::value_type::const_iterator> listProduceUniqueSubstr(const List &list, const typename List::value_type &value) {
	size_t smallest = value.size();
	auto retBegin = value.cbegin(), retEnd = value.cend();
	for(auto s = retBegin; value.cend() != s; ++s) {
		for(auto x = value.cend(); s != x; --x) {
			if((x - s) < smallest) {
				if(listHasSubstr(list, s, x)) {
					break;
				}
				smallest = x - s;
				retBegin = s, retEnd = x;
			}
		}
	} /* Incremental `for()` loops, is a slow method to produce unique substrings; should use binary searches, or look for the standard function which optimizes this. */
	return {retBegin, retEnd};
}
template<class List>
/* Usage: auto it = listOfSubstrFindMatch(resultList.signatures, bytecode)); if(it) {std::cout << "value matches ResultList.signatures[" << it << "]";} */
auto listOfSubstrFindMatch(const List &list, const typename List::value_type &x) {
	for(auto value : list) {
#if PREFERENCE_IS_CSTR
		auto result = memmem(&x[0], strlen(&x[0]), &value[0], strlen(&value[0]));
		if(NULL != result) {
#else /* !PREFERENCE_IS_CSTR */
		auto result = std::search(x.cbegin(), x.cend(), value.cbegin(), value.cend(), [](char ch1, char ch2) { return ch1 == ch2; });
		if(value.cend() != result) {
#endif /* !PREFERENCE_IS_CSTR */
			return result;
		}
	}
	return list.back().cend();
}
template<class List>
/* Usage: if(listOfSubstrHasMatch(resultList.signatures, bytecode)) {std::cout << "value matches ResultList.signatures";} */
const bool listOfSubstrHasMatch(const List &list, const typename List::value_type &x) {
	return list.back().cend() != listOfSubstrFindMatch(list, x);
}

template<class S>
const std::vector<S> explodeToList(const S &s, const S &token) {
	std::vector<S> list;
	for(auto x = s.cbegin(); s.cend() != x; ) {
		auto it = std::search(x, s.cend(), token.cbegin(), token.cend(), [](char ch1, char ch2) { return ch1 == ch2; });
		list.push_back(S(x, it));
		if(s.cend() == x) {
			return list;
		}
		x = it;
	}
	return list;
}
```
`less` [cxx/ClassCns.hxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/ClassCns.hxx)
```
typedef enum CnsMode {
	cnsModeBool, cnsModeChar, cnsModeInt, cnsModeUint, cnsModeFloat, cnsModeDouble,
	cnsModeVectorBool, cnsModeVectorChar, cnsModeVectorInt, cnsModeVectorUint, cnsModeVectorFloat, cnsModeVectorDouble,
#ifdef CXX_17
	cnsModeString = cnsModeVectorChar /* std::string == std::vector<char> */
#else /* else !def CXX_17 */
/* https://stackoverflow.com/questions/5115166/how-to-construct-a-stdstring-from-a-stdvectorchar */
	cnsModeString
#endif /* def CXX_17 else */
} CnsMode;

/* @pre @code std::ifstream(executable); @endcode */
const int posixExec(const std::string &executable, const std::string &argsS = "", const std::string &envVarsS = "");
typedef class Cns {
public:
	virtual const bool hasImplementation() const {return typeid(Cns) != typeid(this);}
	virtual const bool isInitialized() const {return initialized;}
	virtual void setInitialized(const bool is) {initialized = is;}
	virtual void setInputMode(CnsMode x) {inputMode = x;}
	virtual void setOutputMode(CnsMode x) {outputMode = x;}
	virtual void setInputNeurons(size_t x) {inputNeurons = x;}
	virtual void setOutputNeurons(size_t x) {outputNeurons = x;}
	virtual void setLayersOfNeurons(size_t x) {layersOfNeurons = x;}
	virtual void setNeuronsPerLayer(size_t x) {neuronsPerLayer = x;}
	/* @throw bad_alloc
	 * @pre @code hasImplementation() @endcode
	 * @post @code isInitialized() @endcode */
	// template<Intput, Output> virtual void setupSynapses(std::vector<std::tuple<Input, Output>> inputsToOutputs); /* C++ does not support templates of virtual functions ( https://stackoverflow.com/a/78440416/24473928 ) */
	/* @pre @code isInitialized() @endcode */
	// template<Input, Output> virtual const Output process(Input input);
#define templateWorkaround(CNS_MODE, TYPEDEF) \
	virtual void setupSynapses(const std::vector<const std::tuple<TYPEDEF, const bool>> &inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeBool;}\
	virtual void setupSynapses(const std::vector<const std::tuple<TYPEDEF, const char>> &inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeChar;}\
	virtual void setupSynapses(const std::vector<const std::tuple<TYPEDEF, const int>> &inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeInt;}\
	virtual void setupSynapses(const std::vector<const std::tuple<TYPEDEF, const unsigned int>> &inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeUint;}\
	virtual void setupSynapses(const std::vector<const std::tuple<TYPEDEF, float>> &inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeFloat;}\
	virtual void setupSynapses(const std::vector<const std::tuple<TYPEDEF, const double>> &inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeDouble;}\
	virtual void setupSynapses(const std::vector<const std::tuple<TYPEDEF, const std::vector<bool>>> &inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeVectorBool;}\
	virtual void setupSynapses(const std::vector<const std::tuple<TYPEDEF, const std::vector<char>>> &inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeVectorChar;}\
	virtual void setupSynapses(const std::vector<const std::tuple<TYPEDEF, const std::vector<int>>> &inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeVectorInt;}\
	virtual void setupSynapses(const std::vector<const std::tuple<TYPEDEF, const std::vector<unsigned int>>> &inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeVectorUint;}\
	virtual void setupSynapses(const std::vector<const std::tuple<TYPEDEF, const std::vector<float>>> &inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeVectorFloat;}\
	virtual void setupSynapses(const std::vector<const std::tuple<TYPEDEF, const std::vector<double>>> &inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeVectorDouble;}\
	virtual void setupSynapses(const std::vector<const std::tuple<TYPEDEF, const std::string>> &inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeString;}\
	virtual const bool processToBool(TYPEDEF input) const {assert(CNS_MODE == inputMode && cnsModeBool == outputMode); return 0;}\
	virtual const char processToChar(TYPEDEF input) const {assert(CNS_MODE == inputMode && cnsModeChar == outputMode); return 0;}\
	virtual const int processToInt(TYPEDEF input) const {assert(CNS_MODE == inputMode && cnsModeInt == outputMode); return 0;}\
	virtual const unsigned int processToUint(TYPEDEF input) const {assert(CNS_MODE == inputMode && cnsModeUint == outputMode); return 0;}\
	virtual const float processToFloat(TYPEDEF input) const {assert(CNS_MODE == inputMode && cnsModeFloat == outputMode); return 0;}\
	virtual const double processToDouble(TYPEDEF input) const {assert(CNS_MODE == inputMode && cnsModeDouble == outputMode); return 9;}\
	virtual const std::vector<bool> processToVectorBool(TYPEDEF input) const {assert(CNS_MODE == inputMode && cnsModeVectorBool == outputMode); return {};}\
	virtual const std::vector<char> processToVectorChar(TYPEDEF input) const {assert(CNS_MODE == inputMode && cnsModeVectorChar == outputMode); return {};}\
	virtual const std::vector<int> processToVectorInt(TYPEDEF input) const {assert(CNS_MODE == inputMode && cnsModeVectorInt == outputMode); return {};}\
	virtual const std::vector<unsigned int> processToVectorUint(TYPEDEF input) const {assert(CNS_MODE == inputMode && cnsModeVectorUint == outputMode); return {};}\
	virtual std::vector<float> processToVectorFloat(TYPEDEF input) const {assert(CNS_MODE == inputMode && cnsModeVectorFloat == outputMode); return {};}\
	virtual const std::vector<double> processToVectorDouble(TYPEDEF input) const {assert(CNS_MODE == inputMode && cnsModeVectorDouble == outputMode); return {};}\
	virtual const std::string processToString(TYPEDEF input) const {auto val = processToVectorChar(input); return std::string(&val[0], val.size());}
	templateWorkaround(cnsModeBool, const bool)
	templateWorkaround(cnsModeChar, const char)
	templateWorkaround(cnsModeInt, const int)
	templateWorkaround(cnsModeUint, const unsigned int)
	templateWorkaround(cnsModeFloat, const float)
	templateWorkaround(cnsModeDouble, const double)
	templateWorkaround(cnsModeVectorBool, const std::vector<bool>)
	templateWorkaround(cnsModeVectorChar, const std::vector<char>)
	templateWorkaround(cnsModeVectorInt, const std::vector<int>)
	templateWorkaround(cnsModeVectorUint, const std::vector<unsigned int>)
	templateWorkaround(cnsModeVectorFloat, const std::vector<float>)
	templateWorkaround(cnsModeVectorDouble, const std::vector<double>)
	templateWorkaround(cnsModeString, const std::string)
private:
	bool initialized;
	CnsMode inputMode, outputMode;
	size_t inputNeurons, outputNeurons, layersOfNeurons, neuronsPerLayer;
} Cns;

#ifdef USE_HSOM_CNS
typedef class HsomCns : Cns {
/* Work-in-progress (`ClassCns.cxx` for more information): `HSOM` is simple Python-based CNS from https://github.com/CarsonScott/HSOM
 * Examples of howto setup `HSOM` as artificial CNS; https://github.com/CarsonScott/HSOM/tree/master/examples
 * [ https://stackoverflow.com/questions/3286448/calling-a-python-method-from-c-c-and-extracting-its-return-value ] suggests various syntaxes to use for this, with unanswered comments such as "Does this support classes?"
 */
} HsomCns;
#endif /* USE_HSOM_CNS */

#ifdef USE_APXR_CNS
typedef class ApxrCns : Cns {
/* Work-in-progress (`ClassCns.cxx for more information): `apxr` is complex Erlang-based CNS from https://github.com/Rober-t/apxr_run/
 * Examples of howto setup `apxr` as artificial CNS; https://github.com/Rober-t/apxr_run/blob/master/src/examples/
 * "apxr_run" has various FLOSS neural network activation functions (absolute, average, standard deviation, sqrt, sin, tanh, log, sigmoid, cos), plus sensor functions (vector difference, quadratic, multiquadric, saturation [+D-zone], gaussian, cartesian/planar/polar distances): https://github.com/Rober-t/apxr_run/blob/master/src/lib/functions.erl
 * Various FLOSS neuroplastic functions (self-modulation, Hebbian function, Oja's function): https://github.com/Rober-t/apxr_run/blob/master/src/lib/plasticity.erl
 * Various FLOSS neural network input aggregator functions (dot products, product of differences, mult products): https://github.com/Rober-t/apxr_run/blob/master/src/agent_mgr/signal_aggregator.erl
 * Various simulated-annealing functions for artificial neural networks (dynamic [+ random], active [+ random], current [+ random], all [+ random]): https://github.com/Rober-t/apxr_run/blob/master/src/lib/tuning_selection.erl
 * Choices to evolve connections through Darwinian or Lamarkian formulas: https://github.com/Rober-t/apxr_run/blob/master/src/agent_mgr/neuron.erl
 */
} ApxrCns;
#endif /* USE_APXR_CNS */
```
`less` [cxx/ClassCns.cxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/ClassCns.cxx)
```
const int posixExec(const std::string &executable, const std::string &argsS, const std::string &envVarsS) {
#ifdef _POSIX_VERSION
	char *args[] = {
		const_cast<char *>(executable.c_str()),
		const_cast<char *>(argsS.c_str()),
		NULL
	};
	char *envVars[] = {
		const_cast<char *>(envVarsS.c_str()),
		NULL
	};
	return execve(args[0], args, envVars);
#endif /* def _POSIX_VERSION */
}

#ifdef USE_HSOM_CNS
/* Sources: `git clone https://github.com/CarsonScott/HSOM.git`
 * Install: `pip install pynum && pip install json && pip install git+https://github.com/CarsonScott/HSOM.git`
 * Documentation: `less HSOM/README.md` `less HSOM/Documentation.md` */
/* "If you're using Python >3.5, PyString_FromString() is PyUnicode_FromString()" */
#include <Python.h> /* Sources: `pkg install python` */
typedef class HsomCns : Cns { /* TODO. ( https://stackoverflow.com/questions/3286448/calling-a-python-method-from-c-c-and-extracting-its-return-value ) suggests various syntaxes to use for this, with unanswered comments such as "Does this support classes?" */
	//template<Input, Output> void setupSynapses(const std::vector<std::tuple<Input, Output>>) { /* TODO: templates not allowed for virtual functions with C++ ( https://stackoverflow.com/a/78440416/24473928 ), so must produce codes for each combination of inputMode+outputMode */
	void setupSynapses(const std::vector<std::tuple<float, float>>) {
 	setenv("PYTHONPATH",".",1);
 	Py_Initialize();
//  PyRun_SimpleString("import sys; sys.path.append('.')"); PyRun_SimpleString("import hsom; from hsom import SelfOrganizingNetwork;");
#if USE_PYRUN /* Was told not to use PyRun because "PyRun requires all results go to stdout" */
PyRun_SimpleString("import sys; sys.path.append('./HSOM/')");

/* Based off of https://github.com/CarsonScott/HSOM/blob/master/examples/self_organizing_network.py
 * Not sure if `input_size` is "Inputs from each layer to next layer" and `node_count` is "Inputs to HSOM" (process(input.length())) or vice versa, assumed vice versa */

PyRun_SimpleString("import hsom
from hsom import SelfOrganizingNetwork
from random import sample

input_size = " + inputNeurons + "
layer_sizes = []
for x in range(" + layersOfNeurons + "):
	layer_sizes.append(" + neuronsPerLayer + ");
layer_sizes.append(" + outputNeurons + ");
input_percents = [0.2, 0.2, 0.2, 0.2, 0.75, 1.0]
learning_rate = 0.05
boost_factor = 1
node_count = 5
winner_count = 1
initial_range = (-0.5, 0.5)

# Create layersOfNeurons+1 hierarchical layers of sizes = neuronsPerLayer, and outputNeurons for last
self_organizing_network = SelfOrganizingNetwork(
    input_size=input_size,
    layer_sizes=layer_sizes,
    input_percents=input_percents,
    learning_rates=learning_rate,
    boost_factors=boost_factor,
    node_counts=node_count,
    winner_counts=winner_count,
		initial_ranges=initial_range)

# Create a set of sparse samples
samples = []");
	foreach(inputsToOutputs as sample) { /* TODO: templates not allowed for virtual functions with C++ ( https://stackoverflow.com/a/78440416/24473928 ), so must produce codes for each combination of inputMode+outputMode */
		PyRun_SimpleString("samples.append(" + sample.first() +" -> " + sample.last() + ")");
	}
	PyRun_SimpleString("for i in range(200):
    self_organizing_network.train(samples)
	");
#else /* else !USE_PYRUN */
 	PyObject *module = PyImport_ImportModule("hsom")
 	if(NULL == module) {throw "'hsom' module not found";}
	PyObject *selfOrganizingNetwork = PyObject_GetAttrString(module,(char*)"SelfOrganizingNetwork"); /* or	"PyObject *pDict = PyModule_GetDict(module);  PyObject *selfOrganizingNetwork = PyDict_GetItemString(pDict, (char*)"SelfOrganizingNetwork");" */
 	if(NULL == selfOrganizingNetwork || !PyCallable_Check(selfOrganizingNetwork)) {throw "'SelfOrganizingNetwork' object not found";}
 	double result = PyObject_CallFunction(selfOrganizingNetwork, "d", 2.0); /* or "PyObject *pValue=Py_BuildValue("(z)",(char*)"args");	PyObject *pResult=PyObject_CallObject(selfOrganizingNetwork, pValue); if(NULL == pResult) {throw "PyObject_CallObject failed";} double result = PyInt_AsLong(pResult)); Py_DECREF(pValue);" */
 	Py_DECREF(module);
 ~HsomCns() {
#if PYTHON3
 	Py_FinalizeEx();
#else /* else !PYTHON */
 	Py_Finalize();
#endif /* PYTHON3 else */
 }
#endif /* USE_PYRUN else */
} HsomCns;
#endif /* USE_HSOM_CNS */

#ifdef USE_APXR_CNS
/* Sources: `git clone https://github.com/Rober-t/apxr_run.git`
 * Howto install apxr_run: `less apxr_run/README.md` or `lynx https://github.com/Rober-t/apxr_run/blob/master/README.md` */
typedef class ApxrCns : Cns {
/* TODO: https://stackoverflow.com/questions/1811516/integrating-erlang-with-c (first result for "Howto use Erlang functions from C/C++"):
 * ""Port drivers: you can link a C code to the Erlang VM, and access it using port_command."" references https://www.erlang.org/doc/tutorial/c_portdriver.html , which appears to just show howto use C/C++ functions from Erlang (not vice versa)
 * ""C Nodes: With the ei library you can mimic a VM and talk to your Erlang VMs using the Erlang distribution format."" references https://www.erlang.org/doc/man/ei.html , which shows some promises
 * ""The closest thing I know for interfacing Erlang with C++ directly is EPAPI. Of course it relies on the tried and tested C erl_interface that comes standard with the Erlang distribution."" references https://epapi.googlecode.com/ , which returns "404 not found".
 */
} ApxrCns;
#endif /* USE_APXR_CNS */
```
`less` [cxx/VirusAnalysis.hxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/VirusAnalysis.hxx)
```
typedef enum VirusAnalysisResult {
	virusAnalysisAbort = (short)false, /* do not launch */
	virusAnalysisPass = (short)true, /* launch this (sample passes) */
	virusAnalysisRequiresReview, /* submit to hosts to do analysis */
	virusAnalysisContinue /* continue to next tests (is normal; most analyses can not prove that samples pass) */
} VirusAnalysisResult;
static ResultList passList, abortList; /* Stored on disk, all clients use clones of this */
static Cns analysisCns, disinfectionCns; /* maps of synapses + functions to compute with this */

/* if (with example inputs) these functions (`produceAbortListSignatures()`, `produceAnalysisCns()`, `produceDisinfectionCns()`) pass, `return true;`
 * @pre @code analysisCns.hasImplementation() && disinfectionCns.hasImplementation() @endcode */
const bool virusAnalysisTestsThrows();
static const bool virusAnalysisTests() {try {return virusAnalysisTestsThrows();} catch(...) {return false;}}

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
static std::vector<std::string> syscallPotentialDangers = {
	"memopen", "fwrite", "socket", "GetProcAddress", "IsVmPresent"
};
const VirusAnalysisResult staticAnalysis(const PortableExecutable &, const ResultListHash &); /* if(intersection(importedFunctionsList(sample), dangerFunctionsList)) {return RequiresReview;} return Continue;` */

/* Analysis sandbox */
const VirusAnalysisResult sandboxAnalysis(const PortableExecutable &, const ResultListHash &); /* `chroot(strace(sample)) >> outputs; return straceOutputsAnalysis(outputs);` */
static std::vector<std::string> stracePotentialDangers = {"write(*)"};
const VirusAnalysisResult straceOutputsAnalysis(const FilePath &straceDumpPath); /* TODO: regex */

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
const float cnsAnalysisScore(const PortableExecutable &, const ResultListHash &, const Cns &cns = analysisCns);
/* `return (bool)round(cnsAnalysisScore(file, fileHash))`
 * @pre @code cns.isInitialized() @endcode */
const VirusAnalysisResult cnsAnalysis_(const PortableExecutable &file, const ResultListHash &fileHash, const Cns &cns = analysisCns);
const VirusAnalysisResult cnsAnalysis(const PortableExecutable &file, const ResultListHash &fileHash);

static std::map<ResultListHash, VirusAnalysisResult> hashAnalysisCaches, signatureAnalysisCaches, staticAnalysisCaches, cnsAnalysisCaches, sandboxAnalysisCaches; /* RAM-based caches; memoizes results */

typedef const VirusAnalysisResult (*VirusAnalysisFun)(const PortableExecutable &, const ResultListHash &);
static std::vector<typeof(VirusAnalysisFun)> virusAnalyses = {hashAnalysis, signatureAnalysis, staticAnalysis, cnsAnalysis, sandboxAnalysis /* sandbox is slow, so put last*/};
const VirusAnalysisResult virusAnalysis(const PortableExecutable &file); /* auto hash = Sha2(file.bytecode); for(VirusAnalysisFun analysis : virusAnalyses) {analysis(file, hash);} */
static const VirusAnalysisResult submitSampleToHosts(const PortableExecutable &) {return virusAnalysisRequiresReview;} /* TODO: requires compatible hosts to upload to */
```
`less` [cxx/VirusAnalysis.cxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/VirusAnalysis.cxx)
```
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
	const size_t maxPassSize = maxOfSizes(pass.bytecodes);
	const size_t maxAbortSize = maxOfSizes(abort.bytecodes);
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
	cns.setInputNeurons(maxOfSizes(passOrNull.bytecodes));
	cns.setOutputNeurons(maxOfSizes(abortOrNull.bytecodes));
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
```
`less` [cxx/main.cxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/main.cxx)
```
#include "VirusAnalysis.hxx" /* virusAnalysisTestsThrows */
#include "ConversationCns.hxx" /* conversationCnshrows */
#include "Macros.hxx" /* ASSUME EXPECTS ENSURES NOEXCEPT NORETURN */
#include <stdio.h> /* printf */
#include <stdlib.h> /* exit */
namespace Susuwu {
void noExcept() NOEXCEPT;
NORETURN void noReturn();
void noExcept() NOEXCEPT {printf("true");}
void noReturn()  {exit(0);}
int testHarnesses() EXPECTS(1) ENSURES(1) {
	ASSUME(1);
	printf("cxx/Macros.hxx: pass");
	if(virusAnalysisTestsThrows()) {
		printf("cxx/VirusAnalysis.hxx: pass");
	}
	if(conversationCnsTestsThrows()) {
		printf("cxx/ConversationCns.hxx: pass");
	}
	noReturn();
}
}; /* namespace Susuwu */
int main(int argc, const char **args) {
	return Susuwu::testHarnesses();
}
```
To run most of this fast (lag less,) use `CXXFLAGS` which auto-vectorizes/auto-parallelizes, and to setup CNS synapses (`Cns::setupSynapses()`) fast, use _TensorFlow_'s `MapReduce`. Resources: [How to have computers process fast](https://swudususuwu.substack.com/p/howto-run-devices-phones-laptops).

For comparison; `produceDisinfectionCns` is close to conversation bots (such as "ChatGPT 4.0" or "Claude-3 Opus",) have such demo as `produceConversationCns`;
`less` [cxx/ConversationCns.hxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/ConversationCns.hxx)
```
static Cns conversationCns;

/* if (with example inputs) these functions (`questionsResponsesFromHosts()` `produceConversationCns()`) pass, `return true;`
 * @throw std::bad_alloc
 * @throw std::logic_error
 * @pre @code conversationCns.hasImplementation() @endcode */
const bool conversationCnsTestsThrows();
static const bool conversationCnsTests() { try{ return conversationCnsTestsThrows(); } catch(...) { return false; }}
static std::vector<FilePath> conversationDefaultHosts = {
/* Universal Resources Locators of hosts which `questionsResponsesFromHosts()` uses
 * Wikipedia is a special case; has compressed downloads of databases ( https://wikipedia.org/wiki/Wikipedia:Database_download )
 * Github is a special case; has compressed downloads of repositories ( https://docs.github.com/en/get-started/start-your-journey/downloading-files-from-github )
 */
	"https://stackoverflow.com",
	"https://superuser.com",
	"https://quora.com"
};

/* @throw std::bad_alloc
 * @post If no question, `0 == questionsOrNull.bytecodes[x].size()` (new conversation synthesis).
 * If no responses, `0 == responsesOrNull.bytecodes[x].size()` (ignore).
 * `questionsOrNull.signatures[x] = Universal Resource Locator`
 * @code Sha2(ResultList.bytecodes[x]) == ResultList.hashes[x] @endcode */
void questionsResponsesFromHosts(ResultList &questionsOrNull, ResultList &responsesOrNull, const std::vector<FilePath> &hosts = conversationDefaultHosts);
void questionsResponsesFromXhtml(ResultList &questionsOrNull, ResultList &responsesOrNull, const FilePath &filepath = "index.xhtml");
const std::vector<FilePath> conversationParseUrls(const FilePath &filepath = "index.xhtml"); /* TODO: for XML/XHTML could just use [ https://www.boost.io/libraries/regex/ https://github.com/boostorg/regex ] or [ https://www.boost.org/doc/libs/1_85_0/doc/html/property_tree/parsers.html#property_tree.parsers.xml_parser https://github.com/boostorg/property_tree/blob/develop/doc/xml_parser.qbk ] */
const FileBytecode conversationParseQuestion(const FilePath &filepath = "index.xhtml"); /* TODO: regex or XML parser */
const std::vector<FileBytecode> conversationParseResponses(const FilePath &filepath = "index.xhtml"); /* TODO: regex or XML parser */

/* @pre `questionsOrNull` maps to `responsesOrNull`,
 * `0 == questionsOrNull.bytecodes[x].size()` for new conversation synthesis (empty question has responses),
 * `0 == responsesOrNull.bytecodes[x].size()` if should not respond (question does not have answers).
 * @post Can use `conversationCnsProcess(cns, text)` @code cns.isInitialized() @endcode */
void produceConversationCns(const ResultList &questionsOrNull, const ResultList &responsesOrNull, Cns &cns);

/* All clients use is these 2 functions */
/* `return cns.processStringToString(bytecodes);`
 * @pre @code cns.isInitialized() @encode */
const std::string conversationCnsProcess(const Cns &cns, const std::string &bytecode);
/* `while(std::cin >> questions) { std::cout << conversationCnsProcess(questions); }` but more complex
 * @pre @code cns.isInitialized() @encode */
void conversationCnsLoopProcess(const Cns &cns);
```
`less` [cxx/ConversationCns.cxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/ConversationCns.cxx)
```
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
	inputsToOutputs.reserve(questionsOrNull.bytecodes.size());
	for(int x = 0; questionsOrNull.bytecodes.size() > x; ++x) {
		inputsToOutputs.push_back({questionsOrNull.bytecodes[x], responsesOrNull.bytecodes[x]});
	}
	cns.setupSynapses(inputsToOutputs);
}

void questionsResponsesFromHosts(ResultList &questionsOrNull, ResultList &responsesOrNull, const std::vector<FilePath> &hosts) {
	for(auto host : hosts) {
		posixExec("/bin/wget", "'" + host + "/robots.txt' > robots.txt", NULL);
		posixExec("/bin/wget", "'" + host + "' > index.xhtml", NULL);
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
```
========

**Hash resources:**
Is just a checksum (such as Sha-2) of all sample inputs, which maps to "this passes" (or "this does not pass".)
https://wikipedia.org/wiki/Sha-2

**Signature resources:**
Is just a substring (or regex) of infections, which the virus analysis tool checks all executables for; if the signature is found in the executable, do not allow to launch, otherwise launch this.
https://wikipedia.org/wiki/Regex

**Static analysis resources:**
https://github.com/topics/analysis has lots of open source (FLOSS) analysis tools (such as
https://github.com/kylefarris/clamscan,
 which wraps https://github.com/Cisco-Talos/clamav/ ,)
which show how to use hex dumps (or disassembled sources) of the apps/SW (executables) to deduce what the apps/SW do to your OS.
Static analysis (such as Clang/LLVM has) just checks programs for accidental security threats (such as buffer overruns/underruns, or null-pointer-dereferences,) but could act as a basis,
if you add a few extra checks for deliberate vulnerabilities/signs of infection (these are heuristics, so the user should have a choice to quarantine and submit for review, or continue launch of this).
https://github.com/llvm/llvm-project/blob/main/clang/lib/StaticAnalyzer
is part of Clang/LLVM (license is FLOSS,) does static analysis (produces full graphs of each function the SW uses,
plus arguments passed to thus,
so that if the executable violates security, the analysis shows this to you and asks you what to do.)
LLVM is lots of files, Phasar is just it’s static analysis:
https://github.com/secure-software-engineering/phasar

Example outputs (tests “_Fdroid.apk_”) from _VirusTotal_, of [static analysis](https://www.virustotal.com/gui/file/dc3bb88f6419ee7dde7d1547a41569aa03282fe00e0dc43ce035efd7c9d27d75/details) + [2 sandboxes](https://www.virustotal.com/gui/file/dc3bb88f6419ee7dde7d1547a41569aa03282fe00e0dc43ce035efd7c9d27d75/behavior);
the false positive outputs (from _VirusTotal_'s **Zenbox**) show the purpose of manual review.

**Sandbox resources:**
As opposed to static analysis of the executables hex (or disassembled sources,)
sandboxes perform chroot + functional analysis.
https://wikipedia.org/wiki/Valgrind is just meant to locate accidental security vulnerabilities, but is a common example of functional analysis.
If compliant to POSIX (each Linux OS is), tools can use:
 `chroot()` (run `man chroot` for instructions) so that the programs you test cannot alter stuff out of the test;
 plus can use `strace()` (run `man strace` for instructions, or look at https://opensource.com/article/19/10/strace
https://www.geeksforgeeks.org/strace-command-in-linux-with-examples/ ) which hooks all system calls and saves logs for functional analysis.
Simple sandboxes just launch programs with "chroot()"+"strace()" for a few seconds,
with all outputs sent for manual reviews;
if more complex, has heuristics to guess what is important (in case of lots of submissions, so manual reviews have less to do.)

Autonomous sandboxes (such as Virustotal's) use full outputs from all analyses,
 with calculus to guess if the app/SW is cool to us
 (thousands of rules such as "Should not alter files of other programs unless prompted to through OS dialogs", "Should not perform network access unless prompted to from you", "Should not perform actions leading to obfuscation which could hinder analysis",)
 which, if violated, add to the executables "danger score" (which the analysis results page shows you.)

**CNS resources:**
Once the virus analysis tool has static+functional analysis (+ sandbox,) the next logical move is to do artificial CNS.
Just as (if humans grew trillions of neurons plus thousands of layers of cortices) one of us could parse all databases of infections (plus samples of fresh apps/SW) to setup our synapses to parse hex dumps of apps/SW (to allow us to revert all infections to fresh apps/SW, or if the whole thing is an infection just block,)
so too could artificial CNS (with trillions of artificial neurons) do this:
For analysis, pass training inputs mapped to outputs (infection -> block, fresh apps/SW -> pass) to artificial CNS;
To undo infections (to restore to fresh apps/SW,)
inputs = samples of all (infections or fresh apps/SW,)
outputs = EOF/null (if is infection that can not revert to fresh apps/SW,) or else outputs = fresh apps/SW;
To setup synapses, must have access to huge sample databases (such as Virustotal's access.)

Github has lots of FLOSS (Open Source Softwares) simulators of CNS at https://github.com/topics/artificial-neural-network which have uses to do conversations (such as "ChatGPT 4.0" or "Claude-3 Opus",) but not close to complex enough to house human consciousness: https://github.com/CarsonScott/HSOM

"apxr_run" (https://github.com/Rober-t/apxr_run/ , license is FLOSS) is almost complex enough to house human consciousness;
"apxr_run" has various FLOSS neural network activation functions (absolute, average, standard deviation, sqrt, sin, tanh, log, sigmoid, cos), plus sensor functions (vector difference, quadratic, multiquadric, saturation [+D-zone], gaussian, cartesian/planar/polar distances): https://github.com/Rober-t/apxr_run/blob/master/src/lib/functions.erl
Various FLOSS neuroplastic functions (self-modulation, Hebbian function, Oja's function): https://github.com/Rober-t/apxr_run/blob/master/src/lib/plasticity.erl
Various FLOSS neural network input aggregator functions (dot products, product of differences, mult products): https://github.com/Rober-t/apxr_run/blob/master/src/agent_mgr/signal_aggregator.erl
Various simulated-annealing functions for artificial neural networks (dynamic [+ random], active [+ random], current [+ random], all [+ random]): https://github.com/Rober-t/apxr_run/blob/master/src/lib/tuning_selection.erl
Choices to evolve connections through Darwinian or Lamarkian formulas: [https://github.com/Rober-t/apxr_run/blob/master/src/agent_mgr/neuron.erl](https://github.com/Rober-t/apxr_run/blob/master/src/agent_mgr/signal_aggregator.erl)

Simple to convert Erlang functions to Java/C++ (to reuse for fast programs;
the syntax is close to Lisp's.

Examples of howto setup APXR as artificial CNS; https://github.com/Rober-t/apxr_run/blob/master/src/examples/
Examples of howto setup HSOM as artificial CNS; https://github.com/CarsonScott/HSOM/tree/master/examples
Simple to setup once you have access to databases.

Alternative CNS:
https://swudususuwu.substack.com/p/albatross-performs-lots-of-neural
========

This post was about general methods to produce virus analysis tools,
does not require that local resources do all of this;
For systems with lots of resources, could have local sandboxes/CNS;
For systems with less resources, could just submit samples of unknown apps/SW to hosts to perform analysis;
Could have small local sandboxes (that just run for a few seconds) and small CNS (just billions of neurons with hundreds of layers,
versus the trillions of neurons with thousands of layers of cortices that antivirus hosts would use for this);
Allows reuses of workflows the analysis tool has (could just add (small) local sandboxes, or just add artificial CNS to antivirus hosts for extra analysis.)

