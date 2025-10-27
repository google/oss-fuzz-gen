/*
 * html.c: a libFuzzer target to test several HTML parser interfaces.
 *
 * See Copyright for the status of this software.
 */

#include "fuzz.h"
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/catalog.h>

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
  xmlParserCtxtPtr ctxt;
  htmlDocPtr doc;
  const char *docBuffer;
  size_t maxAlloc, docSize;
  int opts;

  xmlFuzzDataInit(data, size);
  opts = (int)xmlFuzzReadInt(4);
  maxAlloc = xmlFuzzReadInt(4) % (size + 100);

  docBuffer = xmlFuzzReadRemaining(&docSize);
  if (docBuffer == NULL) {
    xmlFuzzDataCleanup();
    return (0);
  }

  /* Pull parser */

  xmlFuzzMemSetLimit(maxAlloc);
  ctxt = htmlNewParserCtxt();
  if (ctxt != NULL) {
    xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
    doc = htmlCtxtReadMemory(ctxt, docBuffer, docSize, NULL, NULL, opts);
    xmlFuzzCheckMallocFailure("htmlCtxtReadMemory", ctxt->errNo == XML_ERR_NO_MEMORY);

    if (doc != NULL) {
      xmlDocPtr copy;

#ifdef LIBXML_OUTPUT_ENABLED
      xmlOutputBufferPtr out;
      const xmlChar *content;

      /*
       * Also test the serializer. Call htmlDocContentDumpOutput with our
       * own buffer to avoid encoding the output. The HTML encoding is
       * excruciatingly slow (see htmlEntityValueLookup).
       */
      out = xmlAllocOutputBuffer(NULL);
      htmlDocContentDumpOutput(out, doc, NULL);
      content = xmlOutputBufferGetContent(out);
      xmlOutputBufferClose(out);
      xmlFuzzCheckMallocFailure("htmlDocContentDumpOutput", content == NULL);
#endif

      copy = xmlCopyDoc(doc, 1);
      xmlFuzzCheckMallocFailure("xmlCopyNode", copy == NULL);
      xmlFreeDoc(copy);

      xmlFreeDoc(doc);
    }

    htmlFreeParserCtxt(ctxt);
  }

  /* Push parser */

#ifdef LIBXML_PUSH_ENABLED
  {
    static const size_t maxChunkSize = 128;
    size_t consumed, chunkSize;

    xmlFuzzMemSetLimit(maxAlloc);
    ctxt = htmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL, XML_CHAR_ENCODING_NONE);

    if (ctxt != NULL) {
      xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
      htmlCtxtUseOptions(ctxt, opts);

      for (consumed = 0; consumed < docSize; consumed += chunkSize) {
        chunkSize = docSize - consumed;
        if (chunkSize > maxChunkSize)
          chunkSize = maxChunkSize;
        htmlParseChunk(ctxt, docBuffer + consumed, chunkSize, 0);
      }

      htmlParseChunk(ctxt, NULL, 0, 1);
      xmlFuzzCheckMallocFailure("htmlParseChunk", ctxt->errNo == XML_ERR_NO_MEMORY);
      xmlFreeDoc(ctxt->myDoc);
      htmlFreeParserCtxt(ctxt);
    }
  }
#endif

  /* Cleanup */

  xmlFuzzMemSetLimit(0);
  xmlFuzzDataCleanup();
  xmlResetLastError();

  return (0);
}
