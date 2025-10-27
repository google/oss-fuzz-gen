#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "context_test.h"
#include "document.h"
#include "html.h"

enum renderer_type { RENDERER_HTML, RENDERER_HTML_TOC, RENDERER_CONTEXT_TEST };

#define DEF_IUNIT 1024
#define DEF_OUNIT 64
#define DEF_MAX_NESTING 16

struct option_data {
  char *basename;
  int done;

  /* time reporting */
  int show_time;

  /* I/O */
  size_t iunit;
  size_t ounit;
  const char *filename;

  /* renderer */
  enum renderer_type renderer;
  int toc_level;
  hoedown_html_flags html_flags;

  /* document */
  uint8_t attr_activation;

  /* parsing */
  hoedown_extensions extensions;
  size_t max_nesting;

  /* link_attributes */
  int link_attributes;
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct option_data opt;
  hoedown_buffer *ib, *ob, *meta;
  hoedown_renderer *renderer = NULL;
  void (*renderer_free)(hoedown_renderer *) = NULL;
  hoedown_document *document;

  /* Parse options */
  opt.basename = "fuzz";
  opt.done = 0;
  opt.show_time = 0;
  opt.iunit = DEF_IUNIT;
  opt.ounit = DEF_OUNIT;
  opt.filename = NULL;
  opt.renderer = RENDERER_HTML;
  opt.toc_level = 0;
  opt.attr_activation = 0;
  // opt.html_flags = 0;
  opt.html_flags = HOEDOWN_HTML_SKIP_HTML | HOEDOWN_HTML_ESCAPE | HOEDOWN_HTML_HARD_WRAP | HOEDOWN_HTML_USE_XHTML | HOEDOWN_HTML_USE_TASK_LIST | HOEDOWN_HTML_LINE_CONTINUE | HOEDOWN_HTML_HEADER_ID | HOEDOWN_HTML_FENCED_CODE_SCRIPT;
  // opt.extensions = 0;
  opt.extensions = HOEDOWN_EXT_TABLES | HOEDOWN_EXT_MULTILINE_TABLES | HOEDOWN_EXT_FENCED_CODE | HOEDOWN_EXT_FOOTNOTES | HOEDOWN_EXT_DEFINITION_LISTS | HOEDOWN_EXT_BLOCKQUOTE_EMPTY_LINE | HOEDOWN_EXT_AUTOLINK | HOEDOWN_EXT_STRIKETHROUGH | HOEDOWN_EXT_UNDERLINE | HOEDOWN_EXT_HIGHLIGHT | HOEDOWN_EXT_QUOTE | HOEDOWN_EXT_SUPERSCRIPT | HOEDOWN_EXT_MATH | HOEDOWN_EXT_NO_INTRA_EMPHASIS | HOEDOWN_EXT_SPACE_HEADERS | HOEDOWN_EXT_MATH_EXPLICIT | HOEDOWN_EXT_HTML5_BLOCKS | HOEDOWN_EXT_NO_INTRA_UNDERLINE_EMPHASIS | HOEDOWN_EXT_DISABLE_INDENTED_CODE | HOEDOWN_EXT_SPECIAL_ATTRIBUTE | HOEDOWN_EXT_SCRIPT_TAGS | HOEDOWN_EXT_META_BLOCK;
  opt.max_nesting = DEF_MAX_NESTING;
  opt.link_attributes = 0;

  /* Read everything */
  ib = hoedown_buffer_new(opt.iunit);
  hoedown_buffer_put(ib, data, size);

  renderer = hoedown_html_renderer_new(opt.html_flags, opt.toc_level);
  renderer_free = hoedown_html_renderer_free;

  /* Perform Markdown rendering */
  ob = hoedown_buffer_new(opt.ounit);
  meta = hoedown_buffer_new(opt.ounit);
  document = hoedown_document_new(renderer, opt.extensions, opt.max_nesting, opt.attr_activation, NULL, meta);

  hoedown_html_renderer_state *state;
  state = (hoedown_html_renderer_state *)renderer->opaque;

  hoedown_document_render(document, ob, ib->data, ib->size);

  /* Cleanup */
  hoedown_buffer_free(ib);
  hoedown_document_free(document);
  renderer_free(renderer);

  /* Write the result to stdout */
  // (void)fwrite(ob->data, 1, ob->size, stdout);
  hoedown_buffer_free(ob);

  hoedown_buffer_free(meta);

  return 0;
}
