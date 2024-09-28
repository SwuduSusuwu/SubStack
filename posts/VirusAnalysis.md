**Virus analysis tools should use local static analysis + sandboxes + artificial CNS (central nervous systems) to secure us**
_[This post](https://swudususuwu.substack.com/p/howto-produce-better-virus-scanners) allows all uses._

Static analysis + sandbox + CNS = 1 second (approx) analysis of **new executables** (protects all app launches,) but _caches_ reduce this to **less than 1ms** (just cost to lookup `ResultList::hashes`, which is `std::unordered_set<decltype(sha2(const FileBytecode &))>`; a hashmap of hashes).

`Licenses: allows all uses ("Creative Commons"/"Apache 2")`
For the most new sources (+ static libs), use apps such as [iSH](https://apps.apple.com/us/app/ish-shell/id1436902243) (for **iOS**) or [Termux](https://play.google.com/store/apps/details?id=com.termux) (for **Android OS**) to run this:
`git clone https://github.com/SwuduSusuwu/SubStack.git && cd ./Substack/ && ./build`
[cxx/Macros.hxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/Macros.hxx)
`less` [cxx/ClassPortableExecutable.hxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/ClassPortableExecutable.hxx)
```
typedef std::string FilePath; /* TODO: `std::char_traits<unsigned char>`, `std::basic_string<unsigned char>("string literal")` */
typedef FilePath FileBytecode; /* Uses `std::string` for bytecode (versus `std::vector`) because:
 * "If you are going to use the data in a string like fashon then you should opt for std::string as using a std::vector may confuse subsequent maintainers. If on the other hand most of the data manipulation looks like plain maths or vector like then a std::vector is more appropriate." -- https://stackoverflow.com/a/1556294/24473928
*/
typedef FilePath FileHash; /* TODO: `std::unordered_set<std::basic_string<unsigned char>>` */
typedef class PortableExecutable : Object {
/* TODO: union of actual Portable Executable (Microsoft) + ELF (Linux) specifications */
public:
	PortableExecutable(FilePath path_ = "") : path(path_) {}
	PortableExecutable(FilePath path_, FileBytecode bytecode_) : path(path_), bytecode(bytecode_) {}
/*TODO: overload on typedefs which map to the same types:	PortableExecutable(FilePath path_, std::string hex_) : path(path_), hex(hex_) {} */
	const std::string getName() const {return "Susuwu::class PortableExecutable";}
	FilePath path; /* Suchas "C:\Program.exe" or "/usr/bin/library.so" */
	FileBytecode bytecode; /* compiled programs; bytecode */
	std::string hex; /* `hexdump(path)`, hexadecimal, for C string functions */
} PortableExecutable;
typedef class PortableExecutableBytecode : public PortableExecutable {
public:
	PortableExecutableBytecode(FilePath path_) : input(path_) {path = path_; if(input.good()) {bytecode = std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());}}
	std::ifstream input;
} PortableExecutableBytecode;
```
`less` [cxx/ClassSha2.cxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/ClassSha2.cxx)
```
/* Uses https://www.rfc-editor.org/rfc/rfc6234#section-8.2.2 */
/* const */ FileHash /* 256 bits, not null-terminated */ sha2(const FileBytecode &bytecode) {
	FileHash result;
	SHA256Context context;
	result.resize(SHA256HashSize);
	SHA256Reset(&context); /* If undefined, link sha224-256.o */
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
typedef struct ResultList /* : Object */ { /* Lists of {metadata, executables (or pages)} */
	const std::string getName() const {return "Susuwu::struct ResultList";}
	std::unordered_set<ResultListHash> hashes; /* Checksums of executables (or pages); to avoid duplicates, plus to do constant ("O(1)") test for which executables (or pages) exists */
	std::vector<ResultListSignature> signatures; /* Smallest substrings (or regexes, or Universal Resource Locators) which can identify `bytecodes`; has uses close to `hashes`, but can match if executables (or pages) have small differences */
	std::vector<ResultListBytecode> bytecodes; /* Whole executables (for `VirusAnalysis`) or webpages (for `AssistantCns`); huge disk usage, just load this for signature synthesis (or CNS backpropagation). */
} ResultList;

template<class List>
const size_t listMaxSize(const List &list) {
#if PREFERENCE_IS_CSTR
	size_t max = 0;
	for(auto it = &list[0]; list.cend() != it; ++it) { const size_t temp = strlen(*it); if(temp > max) {max = temp;}}
	return max; /* WARNING! `strlen()` just does UTF8-strings/hex-strings; if binary, must use `it->size()` */
#else /* else !PREFERENCE_IS_CSTR */
	auto it = std::max_element(list.cbegin(), list.cend(), [](const auto &s, const auto &x) { return s.size() < x.size(); });
	return it->size();
#endif /* PREFERENCE_IS_CSTR else */
}

template<class List>
void listDumpTo(const List &list, std::ostream &os, const bool index, const bool whitespace, const bool pascalValues) {
	size_t index_ = 0;
	os << '{';
	for(const auto &value : list) {
		if(0 != index_) {
			os << ',';
		}
		if(whitespace) {
			os << std::endl << '\t';
		}
		if(index) {
			os << index_;
		}
		if(pascalValues) {
				os << value.size() << value;
		} else {
			os << (index ? "=>0x" : "0x");
			for(char ch : value) {
				os << std::hex << static_cast<int>(ch);
			}
			os << std::dec;
		}
		++index_;
	}
	if(whitespace) {
		os << "\n};" << std::endl;
	} else {
		os << "};";
	}
}
template<class List>
void resultListDumpTo(const List &list, std::ostream &os, const bool index, const bool whitespace, const bool pascalValues) {
	os << "list.hashes" << (whitespace ? " = " : "=");
	listDumpTo(list.hashes, os, index, whitespace, pascalValues);
	os << "list.signatures" << (whitespace ? " = " : "=");
	listDumpTo(list.signatures, os, index, whitespace, pascalValues);
	os << "list.bytecodes" << (whitespace ? " = " : "=");
	listDumpTo(list.bytecodes, os, index, whitespace, pascalValues);
}

template<class List, class List2>
/*	@pre @code !(list.empty() || hashes.full()) @endcode
 *	@post @code !hashes.empty() @endcode */
void listToHashes(const List &list /* ResultList::bytecodes or ResultList::hex*/, List2 &hashes /* ResultList::hashess */) {
	for(const auto &value : list) {
		hashes.insert(sha2(value));
	}
}
/* Usage: if ResultList was not produced with hashes */
static void resultListProduceHashes(ResultList &resultList) {
	listToHashes(resultList.bytecodes, resultList.hashes);
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
/* return list's const_iterator to first instance of x, or list.cend() (if not found) */
auto listFindValue(const List &list, const typename List::value_type &x) {
	return std::find(list.cbegin(), list.cend(), x);
}
template<class List>
const bool listHasValue(const List &list, const typename List::value_type &x) {
	return list.cend() != listFindValue(list, x);
}

template<class List>
const typename List::value_type::const_iterator listDefaultIterator = typename List::value_type::const_iterator(); /* Equates to "Not found" */
template<class List>
/* return list's const_iterator to first instance of Substr{s, x}, or default iterator (if not found)
 * @pre @code s < x @endcode */
typeof listDefaultIterator<List> listFindSubstr(const List &list, typename List::value_type::const_iterator s, typename List::value_type::const_iterator x) {
#pragma unroll
	for(const auto &value : list) {
		auto result = std::search(value.cbegin(), value.cend(), s, x, [](char ch1, char ch2) { return ch1 == ch2; });
		if(value.cend() != result) {
			return result;
		}
	}
	return listDefaultIterator<List>;
}
template<class List>
/* @pre @code s < x @endcode */
const bool listHasSubstr(const List &list, typename List::value_type::const_iterator s, typename List::value_type::const_iterator x) {
	return listDefaultIterator<List> != listFindSubstr(list, s, x);
}
template<class List>
/* Returns shortest substr from `value`, which is not found in `list`
 * Usage: resultList.signatures.push_back({listProduceSignature(resultList.bytecodes, bytecode)); */
const std::tuple<typename List::value_type::const_iterator, typename List::value_type::const_iterator> listProduceSignature(const List &list, const typename List::value_type &value) {
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
	} /* Incremental `for()` loops, is O(n^2 * m) complex formula to produce signatures; should use binary searches, or look for the Standard Template Lib (or Boost) function which optimizes this. */
	return {retBegin, retEnd};
}
template<class List>
/* Usage: auto it = listFindSignatureOfValue(resultList.signatures, input)); if(it) {std::cout << "input has resultList.signatures[" << std::string(it) << "]";} */
typeof listDefaultIterator<List> listFindSignatureOfValue(const List &list, const typename List::value_type &x) {
	for(const auto &value : list) {
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
	return listDefaultIterator<List>;
}
template<class List>
/* Usage: if(listHasSignatureOfValue(resultList.signatures, input)) {std::cout << "input has signature from ResultList.signatures";} */
const bool listHasSignatureOfValue(const List &list, const typename List::value_type &x) {
	return listDefaultIterator<List> != listFindSignatureOfValue(list, x);
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
typedef enum CnsMode : char {
	cnsModeBool, cnsModeChar, cnsModeInt, cnsModeUint, cnsModeFloat, cnsModeDouble,
	cnsModeVectorBool, cnsModeVectorChar, cnsModeVectorInt, cnsModeVectorUint, cnsModeVectorFloat, cnsModeVectorDouble,
#ifdef CXX_17
	cnsModeString = cnsModeVectorChar /* std::string == std::vector<char> */
#else /* else !def CXX_17 */
/* https://stackoverflow.com/questions/5115166/how-to-construct-a-stdstring-from-a-stdvectorchar */
	cnsModeString
#endif /* def CXX_17 else */
} CnsMode;

typedef class Cns : Object {
public:
	const std::string getName() const {return "Susuwu::class Cns";}
	virtual ~Cns() = default;
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
#define templateWorkaround(INPUT_MODE, INPUT_TYPEDEF) \
	virtual void setupSynapses(const std::vector<const std::tuple<INPUT_TYPEDEF, const bool>> &inputsToOutputs) {inputMode = (INPUT_MODE); outputMode = cnsModeBool;}\
	virtual void setupSynapses(const std::vector<const std::tuple<INPUT_TYPEDEF, const char>> &inputsToOutputs) {inputMode = (INPUT_MODE); outputMode = cnsModeChar;}\
	virtual void setupSynapses(const std::vector<const std::tuple<INPUT_TYPEDEF, const int>> &inputsToOutputs) {inputMode = (INPUT_MODE); outputMode = cnsModeInt;}\
	virtual void setupSynapses(const std::vector<const std::tuple<INPUT_TYPEDEF, const unsigned int>> &inputsToOutputs) {inputMode = (INPUT_MODE); outputMode = cnsModeUint;}\
	virtual void setupSynapses(const std::vector<const std::tuple<INPUT_TYPEDEF, float>> &inputsToOutputs) {inputMode = (INPUT_MODE); outputMode = cnsModeFloat;}\
	virtual void setupSynapses(const std::vector<const std::tuple<INPUT_TYPEDEF, const double>> &inputsToOutputs) {inputMode = (INPUT_MODE); outputMode = cnsModeDouble;}\
	virtual void setupSynapses(const std::vector<const std::tuple<INPUT_TYPEDEF, const std::vector<bool>>> &inputsToOutputs) {inputMode = (INPUT_MODE); outputMode = cnsModeVectorBool;}\
	virtual void setupSynapses(const std::vector<const std::tuple<INPUT_TYPEDEF, const std::vector<char>>> &inputsToOutputs) {inputMode = (INPUT_MODE); outputMode = cnsModeVectorChar;}\
	virtual void setupSynapses(const std::vector<const std::tuple<INPUT_TYPEDEF, const std::vector<int>>> &inputsToOutputs) {inputMode = (INPUT_MODE); outputMode = cnsModeVectorInt;}\
	virtual void setupSynapses(const std::vector<const std::tuple<INPUT_TYPEDEF, const std::vector<unsigned int>>> &inputsToOutputs) {inputMode = (INPUT_MODE); outputMode = cnsModeVectorUint;}\
	virtual void setupSynapses(const std::vector<const std::tuple<INPUT_TYPEDEF, const std::vector<float>>> &inputsToOutputs) {inputMode = (INPUT_MODE); outputMode = cnsModeVectorFloat;}\
	virtual void setupSynapses(const std::vector<const std::tuple<INPUT_TYPEDEF, const std::vector<double>>> &inputsToOutputs) {inputMode = (INPUT_MODE); outputMode = cnsModeVectorDouble;}\
	virtual void setupSynapses(const std::vector<const std::tuple<INPUT_TYPEDEF, const std::string>> &inputsToOutputs) {inputMode = (INPUT_MODE); outputMode = cnsModeString;}\
	virtual const bool processToBool(INPUT_TYPEDEF &input) const {assert((INPUT_MODE) == inputMode && cnsModeBool == outputMode); return 0;}\
	virtual const char processToChar(INPUT_TYPEDEF &input) const {assert((INPUT_MODE) == inputMode && cnsModeChar == outputMode); return 0;}\
	virtual const int processToInt(INPUT_TYPEDEF &input) const {assert((INPUT_MODE) == inputMode && cnsModeInt == outputMode); return 0;}\
	virtual const unsigned int processToUint(INPUT_TYPEDEF &input) const {assert((INPUT_MODE) == inputMode && cnsModeUint == outputMode); return 0;}\
	virtual const float processToFloat(INPUT_TYPEDEF &input) const {assert((INPUT_MODE) == inputMode && cnsModeFloat == outputMode); return 0;}\
	virtual const double processToDouble(INPUT_TYPEDEF &input) const {assert((INPUT_MODE) == inputMode && cnsModeDouble == outputMode); return 9;}\
	virtual const std::vector<bool> processToVectorBool(INPUT_TYPEDEF &input) const {assert((INPUT_MODE) == inputMode && cnsModeVectorBool == outputMode); return {};}\
	virtual const std::vector<char> processToVectorChar(INPUT_TYPEDEF &input) const {assert((INPUT_MODE) == inputMode && cnsModeVectorChar == outputMode); return {};}\
	virtual const std::vector<int> processToVectorInt(INPUT_TYPEDEF &input) const {assert((INPUT_MODE) == inputMode && cnsModeVectorInt == outputMode); return {};}\
	virtual const std::vector<unsigned int> processToVectorUint(INPUT_TYPEDEF &input) const {assert((INPUT_MODE) == inputMode && cnsModeVectorUint == outputMode); return {};}\
	virtual std::vector<float> processToVectorFloat(INPUT_TYPEDEF &input) const {assert((INPUT_MODE) == inputMode && cnsModeVectorFloat == outputMode); return {};}\
	virtual const std::vector<double> processToVectorDouble(INPUT_TYPEDEF &input) const {assert((INPUT_MODE) == inputMode && cnsModeVectorDouble == outputMode); return {};}\
	virtual const std::string processToString(INPUT_TYPEDEF &input) const {auto val = processToVectorChar(input); return std::string(&val[0], val.size());}
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
`less` [cxx/ClassSys.hxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/ClassSys.hxx)
```
extern int classSysArgc;
extern const char **classSysArgs;
/* Called from main(), stores {argc, args} into {classSysArgc, classSysArgs}
 * Much simpler to use path from args[0] (versus https://stackoverflow.com/questions/1528298/get-path-of-executable/34109000#34109000)
 * @pre @code (0 < argc && nullptr != args && nullptr != args[0]
 * @post @code (0 < classSysArgc && nullptr != classSysArgs && nullptr != classSysArgs[0] */
void classSysInit(int argc, const char *args[]);

/* `argv = argvS + NULL; envp = envpS + NULL: pid_t pid = fork() || (envpS.empty() ? execv(argv[0], &argv[0]) : execve(argv[0], &argv[0], &envp[0])); return pid;`
 * @pre @code (-1 != access(argv[0], X_OK) @endcode */
const pid_t execvesFork(/* const std::string &pathname, -- `execve` requires `&pathname == &argv[0]` */ const std::vector<const std::string> &argvS = {}, const std::vector<const std::string> &envpS = {});
static const pid_t execvexFork(const std::string &toSh) {return execvesFork({"/bin/sh", "-c", toSh});}
/* `pid_t pid = execvesFork(argvS, envpS); int status; waitpid(pid, &status, 0); return status;}` */
const int execves(const std::vector<const std::string> &argvS = {}, const std::vector<const std::string> &envpS = {});
static const int execvex(const std::string &toSh) {return execves({"/bin/sh", "-c", toSh});}

/* #if _POSIX_VERSION, `return (0 == geteuid());` #elif __WIN32__ `return IsUserAnAdmin();` #endif `return false;` */
const bool hasRoot();
/* #if _POSIX_VERSION, `root ? (seteuid(0) : (seteuid(getuid() || getenv("SUDO_UID")), setuid(geteuid)); return hasRoot();` #endif
 * Usage: setRoot(true); functionsWhichRequireRoot; setRoot(false); */
const bool setRoot(bool root); /* root ? (seteuid(0) : (seteuid(getuid() || atoi(getenv("SUDO_UID"))), setuid(geteuid)); return hasRoot(); */

template<typename Func, typename... Args>
auto templateCatchAll(Func func, const std::string &funcName, Args... args) {
	try {
		return func(args...);
	} catch (const std::exception &ex) {
		SUSUWU_CERR(ERROR, funcName + " {throw std::exception(\"" + ex.what() + "\");}");
		return decltype(func(args...))(); /* `func(args...)`'s default return value; if `int func(args...)`, `return 0;`. If `bool func()`, `return false;` */
	}
}
```
`less` [cxx/ClassSys.cxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/ClassSys.cxx)
```
int classSysArgc = 0;
const char **classSysArgs = {nullptr};
void classSysInit(int argc, const char *args[]) {
	if(0 < (classSysArgc = argc)) {
		assert(nullptr != (classSysArgs = args));
		assert(nullptr != args[0]);
	}
}

const pid_t execvesFork(const std::vector<const std::string> &argvS, const std::vector<const std::string> &envpS) {
#ifdef _POSIX_VERSION
	const pid_t pid = fork();
	if(0 != pid) {
		int status;
		assert(-1 != pid);
		return pid;
	} /* if 0, is fork */
	const std::vector<std::string> argvSmutable = {argvS.cbegin(), argvS.cend()};
	std::vector<char *> argv;
	//for(auto x : argvSmutable) { /* with `fsanitize=address` this triggers "stack-use-after-scope" */
	for(auto x = argvSmutable.begin(); argvSmutable.end() != x; ++x) {
		argv.push_back(const_cast<char *>(x->c_str()));
	}
	argv.push_back(NULL);
	if(envpS.empty()) { /* Reuse LD_PRELOAD to fix https://github.com/termux-play-store/termux-issues/issues/24 */
		execv(argv[0], &argv[0]); /* NORETURN */
	} else {
		std::vector<std::string> envpSmutable = {envpS.cbegin(), envpS.cend()};
		std::vector<char *> envp;
		for(auto x = envpSmutable.begin(); envpSmutable.end() != x; ++x) {
			envp.push_back(const_cast<char *>(x->c_str()));
		}
		envp.push_back(NULL);
		execve(argv[0], &argv[0], &envp[0]); /* NORETURN */
	}
	exit(EXIT_FAILURE); /* execv*() is NORETURN */
#endif /* def _POSIX_VERSION */
}
const int execves(const std::vector<const std::string> &argvS, const std::vector<const std::string> &envpS) {
#ifdef _POSIX_VERSION
	const pid_t pid = execvesFork(argvS, envpS);
	int status;
	waitpid(pid, &status, 0);
	return status;
#endif /* _POSIX_VERSION */
}

const bool hasRoot() {
#ifdef _POSIX_VERSION
	return (0 == geteuid());
#elif defined __WIN32__
	return IsUserAnAdmin();
#else
	SUSUWU_CERR(WARNING, "hasRoot(bool) {#if !(defined _POSIX_VERSION || defined __WIN32__) /* TODO */}");
	return false;
#endif /* def _POSIX_VERSION or def __WIN32__ */
}
const bool setRoot(bool root) {
	if(hasRoot() == root) {
		return root;
	}
#ifdef _POSIX_VERSION
	if(root) {
		if(-1 == seteuid(0)) {
			SUSUWU_CERR(WARNING, "setRoot(true) {(-1 == seteuid(0)) /* stuck as user, perhaps is not setuid executable */}");
		}
#if 0
# ifdef __APPLE__ //TODO: https://stackoverflow.com/questions/2483755/how-to-programmatically-gain-root-privileges/35316538#35316538 says you must execute new processes to do this
# else //TODO: https://stackoverflow.com/questions/34723861/calling-a-c-function-with-root-privileges-without-executing-the-whole-program/70149223#70149223 https://stackoverflow.com/questions/70615937/how-to-run-a-command-as-root-with-c-or-c-with-no-pam-in-linux-with-password-au https://stackoverflow.com/questions/2483755/how-to-programmatically-gain-root-privileges/2483789#2483789 says you must spawn new processes to do this
		/* TODO: polkit? Until this is finished, you must use chmod (to give setuid to executable), or execute new processes (with `sudo`/`su`) if you wish to use firewall/antivirus (which require root) */
# endif /* __APPLE__ else */
#endif /* 0 */
	} else {
/* # ifdef LINUX // TODO: pam_loginuid.so(8) // https://stackoverflow.com/questions/10272784/how-do-i-get-the-users-real-uid-if-the-program-is-run-with-sudo/10272881#10272881
		uid_t sudo_uid = audit_getloginuid();
# else */
		uid_t sudo_uid = getuid();
		if(0 == sudo_uid) {
			char *sudo_uid_str = getenv("SUDO_UID");
			if(NULL == sudo_uid_str) {
				SUSUWU_CERR(WARNING, "setRoot(false) {(NULL == getenv(\"SUDO_UID\")) /* stuck as root */}");
				return true;
			} else {
				sudo_uid = (uid_t)atoi(sudo_uid_str);
				if(-1 == setuid(sudo_uid)) { /* prevent reescalation to root */
					SUSUWU_CERR(WARNING, "setRoot(false) {(-1 == setuid(sudo_uid)) /* can't prevent reescalation to root */}");
				}
			}
		}
//# endif /* def LINUX */
		if(0 == sudo_uid) {
			SUSUWU_CERR(WARNING, "setRoot(false) {(0 == sudo_uid) /*stuck as root */}");
		} else if(-1 == seteuid(sudo_uid)) {
			SUSUWU_CERR(WARNING, "setRoot(false) {(-1 == seteuid(sudo_uid)) /* stuck as root */}");
		}
	}
/* #elif defined __WIN32__ *///TODO: https://stackoverflow.com/questions/6418791/requesting-administrator-privileges-at-run-time says you must spawn new processes to do this
#else
	SUSUWU_CERR(WARNING, "setRoot(bool) {#ifndef _POSIX_VERSION /* TODO */}");
#endif /* _POSIX_VERSION */
	return hasRoot();
}
```
`less` [cxx/VirusAnalysis.hxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/VirusAnalysis.hxx)
```
typedef enum VirusAnalysisHook : char {
	virusAnalysisHookDefault = 0,      /* "real-time" virus scans not initialized */
	virusAnalysisHookQuery   = 0,      /* return present hooks (as enum) */
	virusAnalysisHookClear   = 1 << 0, /* unhook (remove present hooks), then parse rest of bits */
	virusAnalysisHookExec    = 1 << 1, /* hook {execl(), execlp(), execle(), execv(), execvp(), execvpe()} */
	virusAnalysisHookNewFile = 1 << 2, /* hook (for modeNew in {"w+", "a", "a+"}) fwrite((void *)ptr, (size_t)size, (size_t)nmemb, {fopen((const char *)pathname, modeNew), fdopen((int)fd, modeNew), freopen((const char *)pathname, modeNew, (FILE *)stream)}) */
} VirusAnalysisHook;
static const VirusAnalysisHook operator|(VirusAnalysisHook x,  VirusAnalysisHook s) {return static_cast<VirusAnalysisHook>(static_cast<unsigned>(x) | static_cast<unsigned>(s));}
static const VirusAnalysisHook operator&(VirusAnalysisHook x,  VirusAnalysisHook s) {return static_cast<VirusAnalysisHook>(static_cast<unsigned>(x) & static_cast<unsigned>(s));}
static VirusAnalysisHook globalVirusAnalysisHook = virusAnalysisHookDefault; /* Just use virusAnalysisHook() to set+get this, virusAnalysisGetHook() to get this */

typedef enum VirusAnalysisResult : char {
	virusAnalysisAbort = static_cast<char>(false), /* do not launch */
	virusAnalysisPass = static_cast<char>(true), /* launch this (file passes) */
	virusAnalysisRequiresReview, /* submit to hosts to do analysis (infection is difficult to prove, other than known signatures) */
	virusAnalysisContinue /* continue to next tests (is normal; most analyses can not prove a file passes) */
} VirusAnalysisResult; /* if(virusAnalysisAbort != VirusAnalysisResult) {static_assert(true == static_cast<bool>(VirusAnalysisResult));} */

extern ResultList passList, abortList; /* hosts produce, clients initialize shared clones of this from disk */
extern Cns analysisCns, virusFixCns; /* hosts produce, clients initialize shared clones of this from disk */

/* `return (produceAbortListSignatures(EXAMPLES) && produceAnalysisCns(EXAMPLES) && produceVirusFixCns(EXAMPLES)) && virusAnalysisHookTests();`
 * @throw std::bad_alloc, std::runtime_error
 * @pre @code analysisCns.hasImplementation() && virusFixCns.hasImplementation() @endcode */
const bool virusAnalysisTests();
static const bool virusAnalysisTestsNoexcept() NOEXCEPT {return templateCatchAll(virusAnalysisTests, "virusAnalysisTests()");}
const bool virusAnalysisHookTests; /* return for(x: VirusAnalysisHook) {x == virusAnalysisHook(x)};` */
static const bool virusAnalysisHookTestsNoexcept() NOEXCEPT {return templateCatchAll(virusAnalysisHookTests, "virusAnalysisHookTests()");}

/* Use to turn off, query status of, or turn on what other virus scanners refer to as "real-time scans"
 * @pre @code (virusAnalysisHookDefault == virusAnalysisGetHook() || virusAnalysisHookExec == virusAnalysisGetHook() || virusAnalysisHookNewFile == virusAnalysisGetHook() || (virusAnalysisHookExec | virusAnalysisHookNewFile) == virusAnalysisGetHook()) @endcode
 * @post @code (virusAnalysisHookDefault == virusAnalysisGetHook() || virusAnalysisHookExec == virusAnalysisGetHook() || virusAnalysisHookNewFile == virusAnalysisGetHook() || (virusAnalysisHookExec | virusAnalysisHookNewFile) == virusAnalysisGetHook()) @endcode */
const VirusAnalysisHook virusAnalysisHook(VirusAnalysisHook);
static const VirusAnalysisHook virusAnalysisGetHook() {return virusAnalysisHook(virusAnalysisHookQuery);}

const VirusAnalysisResult hashAnalysis(const PortableExecutable &file, const ResultListHash &fileHash); /* `if(abortList[file]) {return Abort;} if(passList[file] {return Pass;} return Continue;` */

/* To produce virus signatures:
 * use passlists (of files reviewed which pass),
 * plus abortlists (of files which failed), such lists as Virustotal has.
 * `produceAbortListSignatures()` is to produce the `abortList.signatures` list, with the smallest substrings unique to infected files; is slow, requires huge database of executables; just hosts should produce this.
 * For clients: Comodo has lists of virus signatures to check against at https://www.comodo.com/home/internet-security/updates/vdp/database.php
 * @throw std::bad_alloc
 * @pre @code passList.bytecodes.size() && abortList.bytecodes.size() && !listsIntersect(passList.bytecodes, abortList.bytecodes) @endcode
 * @post @code abortList.signatures.size() @endcode */
void produceAbortListSignatures(const ResultList &passList, ResultList &abortList);
 /* `if(intersection(file.bytecode, abortList.signatures)) {return VirusAnalysisRequiresReview;} return VirusAnalysisContinue;` 
	* @pre @code abortList.signatures.size() @endcode */
const VirusAnalysisResult signatureAnalysis(const PortableExecutable &file, const ResultListHash &fileHash);

/* Static analysis */
/* @throw bad_alloc */
const std::vector<std::string> importedFunctionsList(const PortableExecutable &file);
extern std::vector<std::string> syscallPotentialDangers;
const VirusAnalysisResult staticAnalysis(const PortableExecutable &file, const ResultListHash &fileHash); /* if(intersection(importedFunctionsList(file), dangerFunctionsList)) {return RequiresReview;} return Continue;` */

/* Analysis sandbox */
const VirusAnalysisResult sandboxAnalysis(const PortableExecutable &file, const ResultListHash &fileHash); /* `chroot(strace(file)) >> outputs; return straceOutputsAnalysis(outputs);` */
extern std::vector<std::string> stracePotentialDangers;
const VirusAnalysisResult straceOutputsAnalysis(const FilePath &straceOutput); /* TODO: regex */

/* Analysis CNS */
/* Setup analysis CNS; is slow to produce (requires access to huge file databases);
but once produced, uses few resources (allow clients to do fast analysis.)
 * @pre @code cns.hasImplementation() && pass.bytecodes.size() && abort.bytecodes.size() @endcode
 * @post @code cns.isInitialized() @endcode */
void produceAnalysisCns(const ResultList &pass, const ResultList &abort,
	const ResultList &unreviewed = ResultList() /* WARNING! Possible danger to use unreviewed files */,
	Cns &cns = analysisCns
);
/* If bytecode resembles `abortList`, `return 0;`. If undecidable (resembles `unreviewedList`), `return 1 / 2`. If resembles passList, `return 1;`
 * @pre @code cns.isInitialized() @endcode */
const float cnsAnalysisScore(const PortableExecutable &file, const ResultListHash &fileHash, const Cns &cns = analysisCns);
/* `return (bool)round(cnsAnalysisScore(file, fileHash))`
 * @pre @code cns.isInitialized() @endcode */
const VirusAnalysisResult cnsAnalysis_(const PortableExecutable &file, const ResultListHash &fileHash, const Cns &cns = analysisCns);
const VirusAnalysisResult cnsAnalysis(const PortableExecutable &file, const ResultListHash &fileHash);

extern std::map<ResultListHash, VirusAnalysisResult> hashAnalysisCaches, signatureAnalysisCaches, staticAnalysisCaches, cnsAnalysisCaches, sandboxAnalysisCaches; /* temporary caches; memoizes results */

typedef const VirusAnalysisResult (*VirusAnalysisFun)(const PortableExecutable &file, const ResultListHash &fileHash);
extern std::vector<typeof(VirusAnalysisFun)> virusAnalyses;

const VirusAnalysisResult virusAnalysis(const PortableExecutable &file); /* auto hash = sha2(file.bytecode); for(VirusAnalysisFun analysis : virusAnalyses) {analysis(file, hash);} */
static const VirusAnalysisResult submitSampleToHosts(const PortableExecutable &file) {return virusAnalysisRequiresReview;} /* TODO: requires compatible hosts to upload to */

/* Setup virus fix CMS, uses more resources than `produceAnalysisCns()` */
/* `abortOrNull` should map to `passOrNull` (`ResultList` is composed of `std::tuple`s, because just `produceVirusFixCns()` requires this),
 * with `abortOrNull->bytecodes[x] = NULL` (or "\0") for new SW synthesis,
 * and `passOrNull->bytecodes[x] = NULL` (or "\0") if infected and CNS can not cleanse this.
 * @pre @code cns.hasImplementation() @endcode
 * @post @code cns.isInitialized() @encode
 */
void produceVirusFixCns(
	const ResultList &passOrNull, /* Expects `resultList->bytecodes[x] = NULL` if does not pass */
	const ResultList &abortOrNull, /* Expects `resultList->bytecodes[x] = NULL` if does pass */
	Cns &cns = virusFixCns
);

/* Uses more resources than `cnsAnalysis()`, can undo infection from bytecodes (restore to fresh SW) 
 * @pre @code cns.isInitialized() @endcode */
const std::string cnsVirusFix(const PortableExecutable &file, const Cns &cns = virusFixCns);
```
`less` [cxx/VirusAnalysis.cxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/VirusAnalysis.cxx)
```
VirusAnalysisHook globalVirusAnalysisHook = virusAnalysisHookDefault; /* Just use virusAnalysisHook() to set+get this, virusAnalysisGetHook() to get this */
ResultList passList, abortList; /* hosts produce, clients initialize shared clones of this from disk */
Cns analysisCns, virusFixCns; /* hosts produce, clients initialize shared clones of this from disk */
std::vector<std::string> syscallPotentialDangers = {
	"memopen", "fwrite", "socket", "GetProcAddress", "IsVmPresent"
};
std::vector<std::string> stracePotentialDangers = {"write(*)"};
std::map<ResultListHash, VirusAnalysisResult> hashAnalysisCaches, signatureAnalysisCaches, staticAnalysisCaches, cnsAnalysisCaches, sandboxAnalysisCaches; /* temporary caches; memoizes results */
std::vector<typeof(VirusAnalysisFun)> virusAnalyses = {hashAnalysis, signatureAnalysis, staticAnalysis, cnsAnalysis, sandboxAnalysis /* sandbox is slow, so put last*/};

const bool virusAnalysisTests() {
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
	resultListProduceHashes(passOrNull);
	resultListProduceHashes(abortOrNull);
	produceAbortListSignatures(passOrNull, abortOrNull);
	std::cout << "resultListDumpTo(.list = passOrNull, .os = std::cout, .index = true, .whitespace = true, .pascalValues = false);" << std::endl;
	resultListDumpTo(passOrNull, std::cout, true, true, false);
	std::cout << "resultListDumpTo(.list = abortOrNull, .os = std::cout, .index = false, .whitespace = false, .pascalValues = false);" << std::endl;
	resultListDumpTo(abortOrNull, std::cout, false, false, false), std::cout << std::endl;
	assert(4 == passOrNull.bytecodes.size());
	assert(passOrNull.bytecodes.size() - 1 /* 2 instances of "SW", discount dup */ == passOrNull.hashes.size());
	assert(0 == passOrNull.signatures.size());
	assert(4 == abortOrNull.bytecodes.size());
	assert(abortOrNull.bytecodes.size() == abortOrNull.hashes.size());
	assert(abortOrNull.bytecodes.size() - 1 /* discount empty substr */ == abortOrNull.signatures.size());
	produceAnalysisCns(passOrNull, abortOrNull, ResultList(), analysisCns);
	produceVirusFixCns(passOrNull, abortOrNull, virusFixCns);
	if(0 < classSysArgc) {
		PortableExecutableBytecode executable(classSysArgs[0]);
		if(virusAnalysisAbort == virusAnalysis(executable)) {
			throw std::runtime_error(SUSUWU_ERRSTR(ERROR, "{virusAnalysisAbort == virusAnalysis(args[0]);} /* With such false positives, shouldn't hook kernel modules */"));
		}
	}
	const bool originalRootStatus = hasRoot();
	setRoot(true);
	virusAnalysisHookTests();
	setRoot(originalRootStatus);
	return true;
}

const bool virusAnalysisHookTests() {
	const VirusAnalysisHook originalHookStatus = virusAnalysisGetHook();
	VirusAnalysisHook hookStatus = virusAnalysisHook(virusAnalysisHookClear | virusAnalysisHookExec);
	if(virusAnalysisHookExec != hookStatus) {
		throw std::runtime_error("`virusAnalysisHook(virusAnalysisHookClear | virusAnalysisHookExec)` == " + std::to_string(hookStatus));
		return false;
	}
	hookStatus = virusAnalysisHook(virusAnalysisHookClear | virusAnalysisHookNewFile);
	if(virusAnalysisHookNewFile != hookStatus) {
		throw std::runtime_error("`virusAnalysisHook(virusAnalysisHookClear | virusAnalysisHookNewFile)` == " + std::to_string(hookStatus));
		return false;
	}
	hookStatus = virusAnalysisHook(virusAnalysisHookClear);
	if(virusAnalysisHookDefault != hookStatus) {
		throw std::runtime_error("`virusAnalysisHook(virusAnalysisHookClear)` == " + std::to_string(hookStatus));
		return false;
	}
	hookStatus = virusAnalysisHook(virusAnalysisHookExec | virusAnalysisHookNewFile);
	if((virusAnalysisHookExec | virusAnalysisHookNewFile) != hookStatus) {
		throw std::runtime_error("`virusAnalysisHook(virusAnalysisExec | virusAnalysisHookNewFile)` == " + std::to_string(hookStatus));
		return false;
	}
	hookStatus = virusAnalysisHook(virusAnalysisHookClear | originalHookStatus);
	if(originalHookStatus != hookStatus) {
		throw std::runtime_error("`virusAnalysisHook(virusAnalysisHookClear | originalHookStatus)` == " + std::to_string(hookStatus));
		return false;
	}
	return true;
}
const VirusAnalysisHook virusAnalysisHook(VirusAnalysisHook virusAnalysisHookStatus) {
	const VirusAnalysisHook originalHookStatus = globalVirusAnalysisHook;
	if(virusAnalysisHookQuery == virusAnalysisHookStatus || originalHookStatus == virusAnalysisHookStatus) {
		return originalHookStatus;
	}
	if(virusAnalysisHookClear & virusAnalysisHookStatus) {
		/* TODO: undo OS-specific "hook"s/"callback"s */
		globalVirusAnalysisHook = virusAnalysisHookDefault;
	}
	if(virusAnalysisHookExec & virusAnalysisHookStatus) {
		/* callbackHook("exec*", */ [](const PortableExecutable &file) { /* TODO: OS-specific "hook"/"callback" for `exec()`/app-launches */
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
		globalVirusAnalysisHook = (globalVirusAnalysisHook | virusAnalysisHookExec);
	}
	if(virusAnalysisHookNewFile & virusAnalysisHookStatus) {
		/* callbackHook("fwrite", */ [](const PortableExecutable &file) { /* TODO: OS-specific "hook"/"callback" for new files/downloads */
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
		globalVirusAnalysisHook = (globalVirusAnalysisHook | virusAnalysisHookNewFile);
	}
	return virusAnalysisGetHook();
}

const VirusAnalysisResult virusAnalysis(const PortableExecutable &file) {
	const auto fileHash = sha2(file.bytecode);
	for(const auto &analysis : virusAnalyses) {
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
		if(listHasSignatureOfValue(abortList.signatures, file.bytecode)) {
			return signatureAnalysisCaches[fileHash] = virusAnalysisAbort;
		}
		return signatureAnalysisCaches[fileHash] = virusAnalysisContinue;
	}
}

void produceAbortListSignatures(const ResultList &passList, ResultList &abortList) {
	abortList.signatures.reserve(abortList.bytecodes.size());
	for(const auto &file : abortList.bytecodes) {
		auto tuple = listProduceSignature(passList.bytecodes, file);
		if(std::get<0>(tuple) < std::get<1>(tuple)) { /* require `(0 < ResultListSignature.size())` to prevent crashes */
			abortList.signatures.push_back(ResultListSignature(std::get<0>(tuple), std::get<1>(tuple)));
		}
	} /* The most simple signature is a substring, but some analyses use regexes. */
}

const std::vector<std::string> importedFunctionsList(const PortableExecutable &file) {
	return {}; /* fixes crash, until importedFunctionsList is implemented/finished */
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
		execvex("cp -r '/usr/home/sandbox/' '/usr/home/sandbox.bak'"); /* or produce FS snapshot */
		execvex("cp '" + file.path + "' '/usr/home/sandbox/'");
		execvex("chroot '/usr/home/sandbox/' \"strace basename '" + file.path + "'\" >> strace.outputs");
		execvex("mv/ '/usr/home/sandbox/strace.outputs' '/tmp/strace.outputs'");
		execvex("rm -r '/usr/home/sandbox/' && mv '/usr/home/sandbox.bak' '/usr/home/sandbox/'"); /* or restore FS snapshot */
		return sandboxAnalysisCaches[fileHash] = straceOutputsAnalysis("/tmp/strace.outputs");
	}
}
const VirusAnalysisResult straceOutputsAnalysis(const FilePath &straceOutput) {
		auto straceDump = std::ifstream(straceOutput);
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
const ResultList &unreviewed /* = ResultList(), WARNING! Possible danger to use unreviewed files */,
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
	for(const auto &bytecodes : pass.bytecodes) {
		inputsToOutputs.push_back({bytecodes, 1.0});
	}
	cns.setupSynapses(inputsToOutputs);
	inputsToOutputs.clear();
	if(!unreviewed.bytecodes.empty()) { /* WARNING! Possible danger to use unreviewed files */
		inputsToOutputs.reserve(unreviewed.bytecodes.size());
		for(const auto &bytecodes : unreviewed.bytecodes) {
			inputsToOutputs.push_back({bytecodes, 1 / 2});
		}
		cns.setupSynapses(inputsToOutputs);
		inputsToOutputs.clear();
	}
	inputsToOutputs.reserve(abort.bytecodes.size());
	for(const auto &bytecodes : abort.bytecodes) {
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
		return cnsAnalysisCaches[fileHash] = static_cast<bool>(round(cnsAnalysisScore(file, cns))) ? virusAnalysisContinue : virusAnalysisRequiresReview;
	}
}
const VirusAnalysisResult cnsAnalysis(const PortableExecutable &file, const ResultListHash &fileHash) {
	return cnsAnalysis_(file, fileHash);
}

void produceVirusFixCns(const ResultList &passOrNull, const ResultList &abortOrNull, Cns &cns /* = virusFixCns */) {
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

const FileBytecode cnsVirusFix(const PortableExecutable &file, const Cns &cns /* = virusFixCns */) {
	return cns.processToString(file.bytecode);
}
```
`less` [cxx/main.cxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/main.cxx)
```
#include "AssistantCns.hxx" /* assistantCnsTestsNoexcept */
#include "ClassSys.hxx" /* execves execvex */
#include "Macros.hxx" /* ASSUME EXPECTS ENSURES NOEXCEPT NORETURN */
#include "VirusAnalysis.hxx" /* virusAnalysisTestsNoexcept */
#include <cstdlib> /* exit EXIT_SUCCESS */
#include <iostream> /* cout flush endl */
namespace Susuwu {
void noExcept() NOEXCEPT;
NORETURN void noReturn();
void noExcept() NOEXCEPT {std::cout << std::flush;}
void noReturn()  {exit(0);}
int testHarnesses() EXPECTS(true) ENSURES(true) {
	std::cout << "cxx/Macros.hxx: " << std::flush;
	ASSUME(true);
	noExcept();
	std::cout << "pass" << std::endl;
	std::cout << "execves(): " << std::flush;
	(EXIT_SUCCESS == execves({"/bin/echo", "pass"})) || std::cout << "error" << std::endl;
	std::cout << "execvex(): " << std::flush;
	(EXIT_SUCCESS == execvex("/bin/echo pass")) || std::cout << "error" << std::endl;
	std::cout << "virusAnalysisTestsNoexcept(): " << std::flush;
	if(virusAnalysisTestsNoexcept()) {
		std::cout << "pass" << std::endl;
	} else {
		std::cout << "error" << std::endl;
	}
	std::cout << "assistantCnsTestsNoexcept(): " << std::flush;
	if(assistantCnsTestsNoexcept()) {
		std::cout << "pass" << std::endl;
	} else {
		std::cout << "error" << std::endl;
	}
	noReturn();
}
}; /* namespace Susuwu */
int main(int argc, const char **args) {
	Susuwu::classSysInit(argc, args);
	return Susuwu::testHarnesses();
}
```
To run most of this fast (lag less,) use `CXXFLAGS` which auto-vectorizes/auto-parallelizes, and to setup CNS synapses (`Cns::setupSynapses()`) fast, use _TensorFlow_'s `MapReduce`. Resources: [How to have computers process fast](https://swudususuwu.substack.com/p/howto-run-devices-phones-laptops).

For comparison; `produceVirusFixCns` is close to assistants (such as "ChatGPT 4.0" or "Claude-3 Opus";) have such demo as `produceAssistantCns`;
`less` [cxx/AssistantCns.hxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/AssistantCns.hxx)
```
extern Cns assistantCns;

/* if (with example inputs) these functions (`questionsResponsesFromHosts()` `produceAssistantCns()`) pass, `return true;`
 * @throw std::bad_alloc
 * @throw std::logic_error
 * @pre @code assistantCns.hasImplementation() @endcode */
const bool assistantCnsTests();
static const bool assistantCnsTestsNoexcept() NOEXCEPT {return templateCatchAll(assistantCnsTests, "assistantCnsTests()");}

/* Universal Resources Locators of hosts which `questionsResponsesFromHosts()` uses
 * Wikipedia is a special case; has compressed downloads of databases ( https://wikipedia.org/wiki/Wikipedia:Database_download )
 * Github is a special case; has compressed downloads of repositories ( https://docs.github.com/en/get-started/start-your-journey/downloading-files-from-github )
 */
extern std::vector<FilePath> assistantDefaultHosts;

/* @throw std::bad_alloc
 * @post If no question, `0 == questionsOrNull.bytecodes[x].size()` (new  synthesis).
 * If no responses, `0 == responsesOrNull.bytecodes[x].size()` (ignore).
 * `questionsOrNull.signatures[x] = Universal Resource Locator`
 * @code sha2(ResultList.bytecodes[x]) == ResultList.hashes[x] @endcode */
void questionsResponsesFromHosts(ResultList &questionsOrNull, ResultList &responsesOrNull, const std::vector<FilePath> &hosts = assistantDefaultHosts);
void questionsResponsesFromXhtml(ResultList &questionsOrNull, ResultList &responsesOrNull, const FilePath &filepath = "index.xhtml");
const std::vector<FilePath> ParseUrls(const FilePath &filepath = "index.xhtml"); /* TODO: for XML/XHTML could just use [ https://www.boost.io/libraries/regex/ https://github.com/boostorg/regex ] or [ https://www.boost.org/doc/libs/1_85_0/doc/html/property_tree/parsers.html#property_tree.parsers.xml_parser https://github.com/boostorg/property_tree/blob/develop/doc/xml_parser.qbk ] */
const FileBytecode ParseQuestion(const FilePath &filepath = "index.xhtml"); /* TODO: regex or XML parser */
const std::vector<FileBytecode> ParseResponses(const FilePath &filepath = "index.xhtml"); /* TODO: regex or XML parser */

/* @pre `questionsOrNull` maps to `responsesOrNull`,
 * `0 == questionsOrNull.bytecodes[x].size()` for new  synthesis (empty question has responses),
 * `0 == responsesOrNull.bytecodes[x].size()` if should not respond (question does not have answers).
 * @post Can use `assistantCnsProcess(cns, text)` @code cns.isInitialized() @endcode */
void produceAssistantCns(const ResultList &questionsOrNull, const ResultList &responsesOrNull, Cns &cns);

/* All clients use is these 2 functions */
/* `return cns.processStringToString(bytecodes);`
 * @pre @code cns.isInitialized() @encode */
const std::string assistantCnsProcess(const Cns &cns, const std::string &bytecode);
/* `while(std::cin >> questions) { std::cout << assistantCnsProcess(questions); }` but more complex
 * @pre @code cns.isInitialized() @encode */
void assistantCnsLoopProcess(const Cns &cns);
```
`less` [cxx/AssistantCns.cxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/AssistantCns.cxx)
```
Cns assistantCns;
std::vector<FilePath> assistantDefaultHosts = {
	"https://stackoverflow.com",
	"https://superuser.com",
	"https://quora.com"
};

const bool assistantCnsTests() {
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
	produceAssistantCns(questionsOrNull, responsesOrNull, assistantCns);
	return true;
}
void produceAssistantCns(const ResultList &questionsOrNull, const ResultList &responsesOrNull, Cns &cns) {
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
	auto noRobots = ParseUrls("robots.txt");
	auto question = ParseQuestion(xhtmlFile);
	if(question.size()) {
		auto questionSha2 = sha2(question);
		if(!listHasValue(questionsOrNull.hashes, questionSha2)) {
			questionsOrNull.hashes.insert(questionSha2);
			auto responses = ParseResponses(xhtmlFile);
			for(auto response : responses) {
				auto questionSha2 = sha2(question);
				auto responseSha2 = sha2(response);
				if(!listHasValue(responsesOrNull.hashes, responseSha2)) {
					questionsOrNull.hashes.insert(questionSha2);
					responsesOrNull.hashes.insert(responseSha2);
					questionsOrNull.bytecodes.push_back(question);
					responsesOrNull.bytecodes.push_back(response);
				}
			}
		}
	}
	auto urls = ParseUrls(xhtmlFile);
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
const std::vector<FilePath> ParseUrls(const FilePath &xhtmlFile) {
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
const FileBytecode ParseQuestion(const FilePath &xhtmlFile) {} /* TODO */
const std::vector<FileBytecode> ParseResponses(const FilePath &xhtmlFile) {} /* TODO */

const std::string assistantCnsProcess(const Cns &cns, const FileBytecode &bytecode) {
	return cns.processToString(bytecode);
}

void assistantCnsLoopProcess(const Cns &cns) {
	std::string bytecode, previous;
	int nthResponse = 0;
	while(std::cin >> bytecode) {
#ifdef IGNORE_PAST_MESSAGES
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
#endif /* IGNORE_PAST_MESSAGES */
 		std::cout << responses.at(nthResponse);
 		previous = bytecode;
 		bytecode += '\n'; /* delimiter separates (and uses) multiple inputs */
	}
}
```
========

**Hash resources:**
Is just a checksum (such as sha-2) of all sample inputs, which maps to "this passes" (or "this does not pass".)
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
is part of Clang/LLVM (license is FLOSS,) does static analysis (emulation produces inputs to functions, formulas analyze stacktraces (+ heap/stack uses) to produce lists of possible unwanted side effects to warn you of); versus [`-fsanitize`](https://github.com/SwuduSusuwu/SubStack/issues/5#issuecomment-2169117084), do not have to recompile to do static analysis. `-fsanitize` requires you to produce inputs, static analysis does this for you.
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

Github has lots of FLOSS (Open Source Softwares) simulators of CNS at https://github.com/topics/artificial-neural-network which have uses to do assistants (such as "ChatGPT 4.0" or "Claude-3 Opus",) but not close to complex enough to house human consciousness:

"HSOM" ( https://github.com/CarsonScott/HSOM , license is FLOSS ) is a simple Python neural map.

"apxr_run" ( https://github.com/Rober-t/apxr_run/ , license is FLOSS ) is almost complex enough to house human consciousness;
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
Allows reuses of workflows which an existant analysis tool has -- can just add (small) local sandboxes, or just add artificial CNS to antivirus hosts for extra analysis.

