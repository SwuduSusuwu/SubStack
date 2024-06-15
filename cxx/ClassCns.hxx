/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#pragma once
#ifndef INCLUDES_cxx_ClassCns_hxx
#define INCLUDES_cxx_ClassCns_hxx
#include <vector> /* std::vector */
#include <string> /* std::string */
#include <tuple> /* std::tuple */
#include <typeinfo> /* typeid */
#include <ctype.h> /* size_t */
#include <assert.h> /* assert */
namespace Susuwu {
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
const int execves(const std::string &executable, const std::vector<const std::string> &argvS = {}, const std::vector<const std::string> &envpS = {});
static const int execvex(const std::string &toSh) {return execves("/bin/sh", {"/bin/sh", "-c", toSh});}
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

/* Possible uses of artificial CNS:
 * Virus analysis; https://swudususuwu.substack.com/p/howto-produce-better-virus-scanners
 * Autonomous robots (includes responses to replies from lots of forums); https://swudususuwu.substack.com/p/program-general-purpose-robots-autonomous
 * Due to understanding of human's consciousness, could undo problems of overpopulation and food shortages, if lots of us become uploads of consciousness (as opposed to below article of how to move whole CNS to robots);
 * https://swudususuwu.substack.com/p/want-this-physical-form-gone-so-wont
 * https://swudususuwu.substack.com/p/destructive-unreversible-upload-of
 */

/* Alternative CNS's: https://swudususuwu.substack.com/p/albatross-performs-lots-of-neural */

/* To process fast (lag less,) use flags which auto-vectorizes/auto-parallelizes; To do `setupConversationCns` fast, use TensorFlow's `MapReduce`:
 * https://swudususuwu.substack.com/p/howto-run-devices-phones-laptops
 */
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassCns_hxx */

