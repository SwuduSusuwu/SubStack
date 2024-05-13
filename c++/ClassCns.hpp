/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDE_GUARD_c__ClassCns__h__
#define INCLUDE_GUARD_c__ClassCns__h__
#include <vector> /* std::vector */
#include <tuple> /* std::tuple */
#include <ctype.h> /* size_t */
#include <assert.h> /* assert */
namespace Susuwu {
typedef enum CnsMode {
	cnsModeBool, cnsModeChar, cnsModeInt, cnsModeUint, cnsModeFloat, cnsModeDouble,
	cnsModeVectorBool, cnsModeVectorChar, cnsModeVectorInt, cnsModeVectorUint, cnsModeVectorFloat, cnsModeVectorDouble,
	cnsModeString = cnsModeVectorChar /* std::string == std::vector<char> */
} CnsMode;

typedef class Cns {
	virtual void setInputMode(CnsMode x) {inputMode = x;}
	virtual void setOutputMode(CnsMode x) {outputMode = x;}
	virtual void setInputNeurons(size_t x) {inputNeurons = x;}
	virtual void setOutputNeurons(size_t x) {outputNeurons = x;}
	virtual void setLayersOfNeurons(size_t x) {layersOfNeurons = x;} 
	virtual void setNeuronsPerLayer(size_t x) {neuronsPerLayer = x;}
	// template<Intput, Output> virtual void setupSynapses(std::vector<std::tuple<Input, Output>> inputsToOutputs); /* C++ does not support templates of virtual functions ( https://stackoverflow.com/a/78440416/24473928 ) */
	// template<Input, Output> virtual const Output process(Input input);
#define templateWorkaround(CNS_MODE, TYPEDEF) \
	virtual void setupSynapses(std::vector<const std::tuple<TYPEDEF, const bool>> inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeBool;}\
	virtual void setupSynapses(std::vector<const std::tuple<TYPEDEF, const char>> inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeChar;}\
	virtual void setupSynapses(std::vector<const std::tuple<TYPEDEF, const int>> inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeInt;}\
	virtual void setupSynapses(std::vector<const std::tuple<TYPEDEF, const unsigned int>> inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeUint;}\
	virtual void setupSynapses(std::vector<const std::tuple<TYPEDEF, const float>> inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeFloat;}\
	virtual void setupSynapses(std::vector<const std::tuple<TYPEDEF, const double>> inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeDouble;}\
	virtual void setupSynapses(std::vector<const std::tuple<TYPEDEF, const std::vector<const bool>>> inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeVectorBool;}\
	virtual void setupSynapses(std::vector<const std::tuple<TYPEDEF, const std::vector<const char>>> inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeVectorChar;}\
	virtual void setupSynapses(std::vector<const std::tuple<TYPEDEF, const std::vector<const int>>> inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeVectorInt;}\
	virtual void setupSynapses(std::vector<const std::tuple<TYPEDEF, const std::vector<const unsigned int>>> inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeVectorUint;}\
	virtual void setupSynapses(std::vector<const std::tuple<TYPEDEF, const std::vector<const float>>> inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeVectorFloat;}\
	virtual void setupSynapses(std::vector<const std::tuple<TYPEDEF, const std::vector<const double>>> inputsToOutputs) {inputMode = CNS_MODE; outputMode = cnsModeVectorDouble;}\
	virtual const bool processToBool(TYPEDEF input) {assert(CNS_MODE == inputMode && cnsModeBool == outputMode);}\
	virtual const char processToChar(TYPEDEF input) {assert(CNS_MODE == inputMode && cnsModeChar == outputMode);}\
	virtual const int processToInt(TYPEDEF input) {assert(CNS_MODE == inputMode && cnsModeInt == outputMode);}\
	virtual const unsigned int processToUint(TYPEDEF input) {assert(CNS_MODE == inputMode && cnsModeUint == outputMode);}\
	virtual const float processToFloat(TYPEDEF input) {assert(CNS_MODE == inputMode && cnsModeFloat == outputMode);}\
	virtual const double processToDouble(TYPEDEF input) {assert(CNS_MODE == inputMode && cnsModeDouble == outputMode);}\
	virtual std::vector<bool> processToVectorBool(TYPEDEF input) {assert(CNS_MODE == inputMode && cnsModeVectorBool == outputMode);}\
	virtual std::vector<char> processToVectorChar(TYPEDEF input) {assert(CNS_MODE == inputMode && cnsModeVectorChar == outputMode);}\
	virtual std::vector<int> processToVectorInt(TYPEDEF input) {assert(CNS_MODE == inputMode && cnsModeVectorInt == outputMode);}\
	virtual std::vector<unsigned int> processToVectorUint(TYPEDEF input) {assert(CNS_MODE == inputMode && cnsModeVectorUint == outputMode);}\
	virtual std::vector<float> processToVectorFloat(TYPEDEF input) {assert(CNS_MODE == inputMode && cnsModeVectorFloat == outputMode);}\
	virtual std::vector<double> processToVectorDouble(TYPEDEF input) {assert(CNS_MODE == inputMode && cnsModeVectorDouble == outputMode);}
	templateWorkaround(cnsModeBool, const bool)
	templateWorkaround(cnsModeChar, const char)
	templateWorkaround(cnsModeInt, const int)
	templateWorkaround(cnsModeUint, const unsigned int)
	templateWorkaround(cnsModeFloat, const float)
	templateWorkaround(cnsModeDouble, const double)
	templateWorkaround(cnsModeVectorBool, const std::vector<const bool>)
	templateWorkaround(cnsModeVectorChar, const std::vector<const char>)
	templateWorkaround(cnsModeVectorInt, const std::vector<const int>)
	templateWorkaround(cnsModeVectorUint, const std::vector<const unsigned int>)
	templateWorkaround(cnsModeVectorFloat, const std::vector<const float>)
	templateWorkaround(cnsModeVectorDouble, const std::vector<const double>)
private:
	CnsMode inputMode, outputMode;
	size_t inputNeurons, outputNeurons, layersOfNeurons, neuronsPerLayer;
} Cns;

#ifdef USE_HSOM_CNS
typedef class HsomCns : Cns {
/* Todo: `HSOM` is simple Python-based CNS from https://github.com/CarsonScott/HSOM 
 * Examples of howto setup `HSOM` as artificial CNS; https://github.com/CarsonScott/HSOM/tree/master/examples
 * [ https://stackoverflow.com/questions/3286448/calling-a-python-method-from-c-c-and-extracting-its-return-value ] suggests various syntaxes to use for this, with unanswered comments such as "Does this support classes?"
 */
	HsomCns();
	~HsomCns();
} HsomCns;
#endif /* USE_HSOM_CNS */

#ifdef USE_APXR_CNS
typedef class ApxrCns : Cns {
/* Todo: `apxr` is complex Erlang-based CNS from https://github.com/Rober-t/apxr_run/
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
#endif /* ndef INCLUDE_GUARD_c__ClassCns__h__ */

