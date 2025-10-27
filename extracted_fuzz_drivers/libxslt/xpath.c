/*
 * xpath.c: libFuzzer target for XPath expressions
 *
 * See Copyright for the status of this software.
 */

#include "fuzz.h"

int LLVMFuzzerInitialize(int *argc_p ATTRIBUTE_UNUSED, char ***argv_p ATTRIBUTE_UNUSED) { return xsltFuzzXPathInit(); }

int LLVMFuzzerTestOneInput(const char *data, size_t size) {
  xmlXPathObjectPtr xpathObj = xsltFuzzXPath(data, size);
  xsltFuzzXPathFreeObject(xpathObj);

  return 0;
}
