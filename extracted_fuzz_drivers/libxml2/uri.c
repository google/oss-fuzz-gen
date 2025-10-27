/*
 * uri.c: a libFuzzer target to test the URI module.
 *
 * See Copyright for the status of this software.
 */

#include "fuzz.h"
#include <libxml/uri.h>

int LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED, char ***argv ATTRIBUTE_UNUSED) {
  xmlFuzzMemSetup();

  return 0;
}

int LLVMFuzzerTestOneInput(const char *data, size_t size) {
  xmlURIPtr uri;
  size_t maxAlloc;
  const char *str1, *str2;
  char *copy;
  xmlChar *strRes;
  int intRes;

  if (size > 10000)
    return (0);

  xmlFuzzDataInit(data, size);
  maxAlloc = xmlFuzzReadInt(4) % (size * 8 + 100);
  str1 = xmlFuzzReadString(NULL);
  str2 = xmlFuzzReadString(NULL);

  xmlFuzzMemSetLimit(maxAlloc);

  xmlFuzzResetMallocFailed();
  intRes = xmlParseURISafe(str1, &uri);
  xmlFuzzCheckMallocFailure("xmlParseURISafe", intRes == -1);

  if (uri != NULL) {
    xmlFuzzResetMallocFailed();
    strRes = xmlSaveUri(uri);
    xmlFuzzCheckMallocFailure("xmlSaveURI", strRes == NULL);
    xmlFree(strRes);
    xmlFreeURI(uri);
  }

  xmlFreeURI(xmlParseURI(str1));

  uri = xmlParseURIRaw(str1, 1);
  xmlFree(xmlSaveUri(uri));
  xmlFreeURI(uri);

  xmlFuzzResetMallocFailed();
  strRes = BAD_CAST xmlURIUnescapeString(str1, -1, NULL);
  xmlFuzzCheckMallocFailure("xmlURIUnescapeString", str1 != NULL && strRes == NULL);
  xmlFree(strRes);

  xmlFree(xmlURIEscape(BAD_CAST str1));

  xmlFuzzResetMallocFailed();
  strRes = xmlCanonicPath(BAD_CAST str1);
  xmlFuzzCheckMallocFailure("xmlCanonicPath", str1 != NULL && strRes == NULL);
  xmlFree(strRes);

  xmlFuzzResetMallocFailed();
  strRes = xmlPathToURI(BAD_CAST str1);
  xmlFuzzCheckMallocFailure("xmlPathToURI", str1 != NULL && strRes == NULL);
  xmlFree(strRes);

  xmlFuzzResetMallocFailed();
  intRes = xmlBuildURISafe(BAD_CAST str2, BAD_CAST str1, &strRes);
  xmlFuzzCheckMallocFailure("xmlBuildURISafe", intRes == -1);
  xmlFree(strRes);

  xmlFree(xmlBuildURI(BAD_CAST str2, BAD_CAST str1));

  xmlFuzzResetMallocFailed();
  intRes = xmlBuildRelativeURISafe(BAD_CAST str2, BAD_CAST str1, &strRes);
  xmlFuzzCheckMallocFailure("xmlBuildRelativeURISafe", intRes == -1);
  xmlFree(strRes);

  xmlFree(xmlBuildRelativeURI(BAD_CAST str2, BAD_CAST str1));

  xmlFuzzResetMallocFailed();
  strRes = xmlURIEscapeStr(BAD_CAST str1, BAD_CAST str2);
  xmlFuzzCheckMallocFailure("xmlURIEscapeStr", str1 != NULL && strRes == NULL);
  xmlFree(strRes);

  copy = (char *)xmlCharStrdup(str1);
  xmlNormalizeURIPath(copy);
  xmlFree(copy);

  xmlFuzzMemSetLimit(0);
  xmlFuzzDataCleanup();

  return 0;
}
