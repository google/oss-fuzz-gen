#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "/src/hoextdown/src/html.h"

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for testing
    if (size < 1) {
        return 0;
    }

    // Allocate a buffer for the tag name, ensuring it is null-terminated
    char tag_name[256];
    size_t tag_name_len = (size < 255) ? size : 255;
    memcpy(tag_name, data, tag_name_len);
    tag_name[tag_name_len] = '\0';

    // Call the function-under-test
    hoedown_html_tag result = hoedown_html_is_tag(data, size, tag_name);

    // Use the result to prevent optimizations that remove the call
    if (result == HOEDOWN_HTML_TAG_NONE) {
        // Do nothing, just a placeholder
    }

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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
