#include <Python.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include "pyutil.h"

#include <iostream>
#include <string>

extern "C" {

static PYCODETYPE *code;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  contrib::initpy(*argv[0]);
  code = (PYCODETYPE *)Py_CompileString(R"py(
try:
    for fn in (
        parsers.isasciistr,
        parsers.asciilower,
        parsers.asciiupper,
        parsers.encodedir,
        parsers.pathencode,
        parsers.lowerencode,
    ):
        try:
            fn(data)
        except UnicodeDecodeError:
            pass  # some functions emit this exception
        except AttributeError:
            # pathencode needs hashlib, which fails to import because the time
            # module fails to import. We should try and fix that some day, but
            # for now we at least get coverage on non-hashencoded codepaths.
            if fn != pathencode:
                raise
        # uncomment this for debugging exceptions
        # except Exception as e:
        #     raise Exception('%r: %r' % (fn, e))
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
  PyObject *mtext = PyBytes_FromStringAndSize((const char *)Data, (Py_ssize_t)Size);
  PyObject *locals = PyDict_New();
  PyDict_SetItemString(locals, "data", mtext);
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
