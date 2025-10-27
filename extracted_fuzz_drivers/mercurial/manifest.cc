#include <Python.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include "FuzzedDataProvider.h"
#include "pyutil.h"

#include <string>

extern "C" {

static PYCODETYPE *code;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  contrib::initpy(*argv[0]);
  code = (PYCODETYPE *)Py_CompileString(R"py(
try:
  lm = parsers.lazymanifest(mdata)
  # iterate the whole thing, which causes the code to fully parse
  # every line in the manifest
  for e, _, _ in lm.iterentries():
      # also exercise __getitem__ et al
      lm[e]
      e in lm
      (e + 'nope') in lm
  lm[b'xyzzy'] = (b'\0' * nlen, 'x')
  # do an insert, text should change
  assert lm.text() != mdata, "insert should change text and didn't: %r %r" % (lm.text(), mdata)
  cloned = lm.filtercopy(lambda x: x != 'xyzzy')
  assert cloned.text() == mdata, 'cloned text should equal mdata'
  cloned.diff(lm)
  del lm[b'xyzzy']
  cloned.diff(lm)
  # should be back to the same
  assert lm.text() == mdata, "delete should have restored text but didn't: %r %r" % (lm.text(), mdata)
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
  FuzzedDataProvider provider(Data, Size);
  Py_ssize_t nodelength = provider.ConsumeBool() ? 20 : 32;
  PyObject *nlen = PyLong_FromSsize_t(nodelength);
  PyObject *mtext = PyBytes_FromStringAndSize((const char *)Data, (Py_ssize_t)Size);
  PyObject *locals = PyDict_New();
  PyDict_SetItemString(locals, "mdata", mtext);
  PyDict_SetItemString(locals, "nlen", nlen);
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
