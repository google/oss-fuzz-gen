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
for inline in (True, False):
    try:
        index, cache = parsers.parse_index2(data, inline)
        index.slicechunktodensity(list(range(len(index))), 0.5, 262144)
        index.stats()
        index.findsnapshots({}, 0)
        10 in index
        for rev in range(len(index)):
            index.reachableroots(0, [len(index)-1], [rev])
            node = index[rev][7]
            partial = index.shortest(node)
            index.partialmatch(node[:partial])
            index.deltachain(rev, None, True)
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
  // Don't allow fuzzer inputs larger than 60k, since we'll just bog
  // down and not accomplish much.
  if (Size > 60000) {
    return 0;
  }
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
