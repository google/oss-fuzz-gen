#include <Python.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include "pyutil.h"

#include "FuzzedDataProvider.h"
#include <iostream>
#include <string>

extern "C" {

static PYCODETYPE *code;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  contrib::initpy(*argv[0]);
  code = (PYCODETYPE *)Py_CompileString(R"py(
try:
    parsers.jsonescapeu8fast(data, paranoid)
except Exception as e:
    pass
    # uncomment this print if you're editing this Python code
    # to debug failures.
    # print(e)
)py",
                                        "fuzzer", Py_file_input);
  if (!code) {
    std::cerr << "failed to compile Python code!" << std::endl;
  }
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider provider(Data, Size);
  bool paranoid = provider.ConsumeBool();
  std::string remainder = provider.ConsumeRemainingBytesAsString();

  PyObject *mtext = PyBytes_FromStringAndSize((const char *)remainder.c_str(), remainder.size());
  PyObject *locals = PyDict_New();
  PyDict_SetItemString(locals, "data", mtext);
  PyDict_SetItemString(locals, "paranoid", paranoid ? Py_True : Py_False);
  PyObject *res = PyEval_EvalCode(code, contrib::pyglobals(), locals);
  if (!res) {
    PyErr_Print();
  }
  Py_XDECREF(res);
  Py_DECREF(locals);
  Py_DECREF(mtext);
  return 0; // Non-zero return values are reserved for future use.
}
}
