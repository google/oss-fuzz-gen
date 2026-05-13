#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "document.h" // Correct path for hoedown_document and related functions
#include "/src/hoextdown/src/buffer.h" // Include necessary for hoedown_buffer
#include "html.h" // Include necessary for hoedown_html_renderer

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    // Initialize a hoedown_renderer object using a specific renderer like HTML
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of hoedown_html_renderer_new
    hoedown_renderer *renderer = hoedown_html_renderer_new(HOEDOWN_HTML_HEADER_ID, 0); // Initialize renderer with appropriate flags
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    // Check if the renderer is successfully created
    if (renderer == NULL) {
        return 0;
    }

    // Create a hoedown_buffer for output
    hoedown_buffer *ob = hoedown_buffer_new(64);

    // Check if the buffer is successfully created
    if (ob == NULL) {
        hoedown_html_renderer_free(renderer);
        return 0;
    }

    // Initialize hoedown_document with all required parameters
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of hoedown_document_new
    hoedown_document *doc = hoedown_document_new(renderer, HOEDOWN_EXT_TABLES, 16, 0, NULL, NULL);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    // Check if the document is successfully created
    if (doc == NULL) {
        hoedown_buffer_free(ob);
        hoedown_html_renderer_free(renderer);
        return 0;
    }

    // Call the function-under-test using the input data
    if (size > 0 && data != NULL) {
        hoedown_document_render(doc, ob, data, size);
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from hoedown_document_render to hoedown_document_render_inline
        // Ensure dataflow is valid (i.e., non-null)
        if (!doc) {
        	return 0;
        }
        uint8_t ret_hoedown_document_ul_item_char_exmnd = hoedown_document_ul_item_char(doc);
        if (ret_hoedown_document_ul_item_char_exmnd < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!doc) {
        	return 0;
        }
        uint8_t ret_hoedown_document_fencedcode_char_wqfgq = hoedown_document_fencedcode_char(doc);
        if (ret_hoedown_document_fencedcode_char_wqfgq < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!doc) {
        	return 0;
        }
        uint8_t ret_hoedown_document_hrule_char_einxk = hoedown_document_hrule_char(doc);
        if (ret_hoedown_document_hrule_char_einxk < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!doc) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ob) {
        	return 0;
        }
        hoedown_document_render_inline(doc, ob, &ret_hoedown_document_fencedcode_char_wqfgq, (size_t )ret_hoedown_document_hrule_char_einxk);
        // End mutation: Producer.APPEND_MUTATOR
        
}

    // Clean up
    hoedown_document_free(doc);
    hoedown_buffer_free(ob);
    hoedown_html_renderer_free(renderer);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
