#ifndef INCLUDE_GUARD_c__ClassCns__c__
#define INCLUDE_GUARD_c__ClassCns__c__
#include <ctype.h> /* size_t */
#include "ClassCns.h" /* CnsMode */
namespace Susuwu {
#ifdef USE_HSOM /* Todo. ( https://stackoverflow.com/questions/3286448/calling-a-python-method-from-c-c-and-extracting-its-return-value ) suggests various syntaxes to use for this, with unanswered comments such as "Does this support classes?" */
/* "If you're using Python >3.5, PyString_FromString() is PyUnicode_FromString()" */
#include <Python.h>
typedef class HsomCns : Cns { /* https://github.com/CarsonScott/HSOM */
 HsomCns() {
  setenv("PYTHONPATH",".",1);
  Py_Initialize();
//  PyRun_SimpleString("import sys; sys.path.append('.')"); PyRun_SimpleString("import hsom; from hsom import SelfOrganizingNetwork;"); /* Was told not to use PyRun because "PyRun requires all results go to stdout" */
  PyObject *module = PyImport_ImportModule("hsom")
  if(NULL == module) {throw "'hsom' module not found";}
	PyObject *selfOrganizingNetwork = PyObject_GetAttrString(module,(char*)"SelfOrganizingNetwork"); /* or	"PyObject *pDict = PyModule_GetDict(module);  PyObject *selfOrganizingNetwork = PyDict_GetItemString(pDict, (char*)"SelfOrganizingNetwork");" */
  if(NULL == selfOrganizingNetwork || !PyCallable_Check(selfOrganizingNetwork)) {throw "'SelfOrganizingNetwork' object not found";}
  double result = PyObject_CallFunction(selfOrganizingNetwork, "d", 2.0); /* or "PyObject *pValue=Py_BuildValue("(z)",(char*)"args");	PyObject *pResult=PyObject_CallObject(selfOrganizingNetwork, pValue); if(NULL == pResult) {throw "PyObject_CallObject failed";} double result = PyInt_AsLong(pResult)); Py_DECREF(pValue);" */
  Py_DECREF(module);
 ~HsomCns() {
#if PYTHON3
  Py_FinalizeEx();
#else
  Py_Finalize();
#endif /* PYTHON3 */
 }
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
} HsomCns;
#endif /* Todo */

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
#endif /* ndef INCLUDE_GUARD_c__ClassCns__c__ */

