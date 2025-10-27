#include <Python.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include <string>

#include "pyutil.h"

extern "C" {

static PYCODETYPE *code;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  contrib::initpy(*argv[0]);
  code = (PYCODETYPE *)Py_CompileString(R"py(
def maybeint(s, default):
    try:
        return int(s)
    except ValueError:
        return default
try:
    parts = data.split('\0', 2)
    if len(parts) == 3:
        offset, stop, data = parts
    elif len(parts) == 2:
        stop, data = parts
        offset = 0
    else:
        offset = stop = 0
    offset, stop = maybeint(offset, 0), maybeint(stop, len(data))
    parsers.fm1readmarkers(data, offset, stop)
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
  PyObject *text = PyBytes_FromStringAndSize((const char *)Data, (Py_ssize_t)Size);
  PyObject *locals = PyDict_New();
  PyDict_SetItemString(locals, "data", text);
  PyObject *res = PyEval_EvalCode(code, contrib::pyglobals(), locals);
  if (!res) {
    PyErr_Print();
  }
  Py_XDECREF(res);
  Py_DECREF(locals);
  Py_DECREF(text);
  return 0; // Non-zero return values are reserved for future use.
}
}
