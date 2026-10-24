#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/hoextdown/src/buffer.h"
#include "document.h"

static hoedown_renderer dummy_renderer = {0};

int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Initialize two buffers
    hoedown_buffer *buffer1 = hoedown_buffer_new(64);
    hoedown_buffer *buffer2 = hoedown_buffer_new(64);

    if (!buffer1 || !buffer2) {
        if (buffer1) hoedown_buffer_free(buffer1);
        if (buffer2) hoedown_buffer_free(buffer2);
        return 0;
    }

    // Create a document processor
    hoedown_document *document = hoedown_document_new(
        &dummy_renderer,
        HOEDOWN_EXT_AUTOLINK | HOEDOWN_EXT_STRIKETHROUGH,
        1, // Ensure max_nesting is non-zero
        0,
        NULL,
        buffer1
    );

    if (document) {
        // Render inline Markdown
        hoedown_document_render_inline(document, buffer2, Data, Size);

        // Free the document
        hoedown_document_free(document);
    }

    // Free the buffers
    hoedown_buffer_free(buffer1);
    hoedown_buffer_free(buffer2);

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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
