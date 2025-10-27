#include <Python.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include "pyutil.h"

#include <string>

extern "C" {

static PYCODETYPE *code;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  contrib::initpy(*argv[0]);
  code = (PYCODETYPE *)Py_CompileString(R"py(
try:
  files = mdata.split('\n')
  d = parsers.dirs(files)
  list(d)
  'a' in d
  if files:
    files[0] in d
except Exception as e:
  pass
  # uncomment this print if you're editing this Python code
  # to debug failures.
  # print e
)py",
                                        "fuzzer", Py_file_input);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // Don't allow fuzzer inputs larger than 100k, since we'll just bog
  // down and not accomplish much.
  if (Size > 100000) {
    return 0;
  }
  PyObject *mtext = PyBytes_FromStringAndSize((const char *)Data, (Py_ssize_t)Size);
  PyObject *locals = PyDict_New();
  PyDict_SetItemString(locals, "mdata", mtext);
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
