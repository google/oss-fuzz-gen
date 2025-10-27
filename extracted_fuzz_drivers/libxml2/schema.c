/*
 * schema.c: a libFuzzer target to test the XML Schema processor.
 *
 * See Copyright for the status of this software.
 */

#include "fuzz.h"
#include <libxml/catalog.h>
#include <libxml/xmlschemas.h>

int LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED, char ***argv ATTRIBUTE_UNUSED) {
  xmlFuzzMemSetup();
  xmlInitParser();
#ifdef LIBXML_CATALOG_ENABLED
  xmlInitializeCatalog();
  xmlCatalogSetDefaults(XML_CATA_ALLOW_NONE);
#endif

  return 0;
}

int LLVMFuzzerTestOneInput(const char *data, size_t size) {
  xmlSchemaParserCtxtPtr pctxt;
  size_t maxAlloc;

  if (size > 50000)
    return (0);

  maxAlloc = xmlFuzzReadInt(4) % (size + 100);

  xmlFuzzDataInit(data, size);
  xmlFuzzReadEntities();

  xmlFuzzMemSetLimit(maxAlloc);
  pctxt = xmlSchemaNewParserCtxt(xmlFuzzMainUrl());
  xmlSchemaSetParserStructuredErrors(pctxt, xmlFuzzSErrorFunc, NULL);
  xmlSchemaSetResourceLoader(pctxt, xmlFuzzResourceLoader, NULL);
  xmlSchemaFree(xmlSchemaParse(pctxt));
  xmlSchemaFreeParserCtxt(pctxt);

  xmlFuzzMemSetLimit(0);
  xmlFuzzDataCleanup();
  xmlResetLastError();

  return (0);
}
