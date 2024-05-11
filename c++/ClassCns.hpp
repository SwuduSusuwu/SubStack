/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDE_GUARD_c__ClassCns__h__
#define INCLUDE_GUARD_c__ClassCns__h__
#include <ctype.h> /* size_t */
namespace Susuwu {
typedef enum CnsMode {
	cnsModeInt, cnsModeUint, cnsModeFloat, cnsModeDouble, cnsModeChar,
	cnsModeVectorInt, cnsModeVectorUint, cnsModeVectorFloat, cnsModeVectorDouble, cnsModeVectorChar,
	cnsModeString = cnsModeVectorChar
} CnsMode;

typedef class Cns {
	template<Input>
 	virtual void inputsToSetup(Input inputs);
	template<Output>
 	virtual void outputsToSetup(Output outputs);
	virtual void setInputMode(CnsMode);
	virtual void setOutputMode(CnsMode);
	virtual void setInputNeurons(size_t x);
	virtual void setOutputNeurons(size_t x);
	virtual void setLayersOfNeurons(size_t x);
	virtual void setNeuronsPerLayer(size_t x);
	virtual void setupSynapses();
	template<Input, Output>
 	virtual const Output process(Input input);
} Cns;

#ifdef USE_HSOM
typedef class HsomCns : Cns {
/* Todo: `HSOM` is simple Python-based CNS from https://github.com/CarsonScott/HSOM 
 * Examples of howto setup `HSOM` as artificial CNS; https://github.com/CarsonScott/HSOM/tree/master/examples
 * [ https://stackoverflow.com/questions/3286448/calling-a-python-method-from-c-c-and-extracting-its-return-value ] suggests various syntaxes to use for this, with unanswered comments such as "Does this support classes?"
 */
	HsomCns();
	~HsomCns();
} HsomCns;
#endif /* USE_HSOM */

#ifdef USE_APXR
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
#endif /* USE_APRXR */

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

