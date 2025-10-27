/*
 * xml.c: a libFuzzer target to test several XML parser interfaces.
 *
 * See Copyright for the status of this software.
 */

#include "fuzz.h"
#include <libxml/catalog.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlsave.h>

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
  xmlDocPtr doc;
  const char *docBuffer, *docUrl;
  size_t maxAlloc, docSize;
  int opts;

  xmlFuzzDataInit(data, size);
  opts = (int)xmlFuzzReadInt(4);
  /*
   * Disable options that are known to cause timeouts
   */
  opts &= ~XML_PARSE_XINCLUDE & ~XML_PARSE_DTDVALID & ~XML_PARSE_SAX1;
  maxAlloc = xmlFuzzReadInt(4) % (size + 100);

  xmlFuzzReadEntities();
  docBuffer = xmlFuzzMainEntity(&docSize);
  docUrl = xmlFuzzMainUrl();
  if (docBuffer == NULL)
    goto exit;

  /* Pull parser */

  xmlFuzzMemSetLimit(maxAlloc);
  ctxt = xmlNewParserCtxt();
  if (ctxt != NULL) {
    xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
    xmlCtxtSetResourceLoader(ctxt, xmlFuzzResourceLoader, NULL);
    doc = xmlCtxtReadMemory(ctxt, docBuffer, docSize, docUrl, NULL, opts);
    xmlFuzzCheckMallocFailure("xmlCtxtReadMemory", doc == NULL && ctxt->errNo == XML_ERR_NO_MEMORY);

    if (doc != NULL) {
#ifdef LIBXML_OUTPUT_ENABLED
      xmlBufferPtr buffer;
      xmlSaveCtxtPtr save;

      /* Also test the serializer. */
      buffer = xmlBufferCreate();
      save = xmlSaveToBuffer(buffer, NULL, 0);
      if (save != NULL) {
        int errNo;

        xmlSaveDoc(save, doc);
        errNo = xmlSaveFinish(save);
        xmlFuzzCheckMallocFailure("xmlSaveDoc", errNo == XML_ERR_NO_MEMORY);
      }
      xmlBufferFree(buffer);
#endif
      xmlFreeDoc(doc);
    }

    xmlFreeParserCtxt(ctxt);
  }

  /* Push parser */

#ifdef LIBXML_PUSH_ENABLED
  {
    static const size_t maxChunkSize = 128;
    size_t consumed, chunkSize;

    xmlFuzzMemSetLimit(maxAlloc);
    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, docUrl);
    if (ctxt != NULL) {
      xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
      xmlCtxtSetResourceLoader(ctxt, xmlFuzzResourceLoader, NULL);
      xmlCtxtUseOptions(ctxt, opts);

      for (consumed = 0; consumed < docSize; consumed += chunkSize) {
        chunkSize = docSize - consumed;
        if (chunkSize > maxChunkSize)
          chunkSize = maxChunkSize;
        xmlParseChunk(ctxt, docBuffer + consumed, chunkSize, 0);
      }

      xmlParseChunk(ctxt, NULL, 0, 1);
      xmlFuzzCheckMallocFailure("xmlParseChunk", ctxt->errNo == XML_ERR_NO_MEMORY);
      xmlFreeDoc(ctxt->myDoc);
      xmlFreeParserCtxt(ctxt);
    }
  }
#endif

exit:
  xmlFuzzMemSetLimit(0);
  xmlFuzzDataCleanup();
  xmlResetLastError();
  return (0);
}
