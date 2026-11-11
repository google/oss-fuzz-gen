#include <stdint.h>
#include <stddef.h>
#include "/src/hoextdown/src/html.h"

int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
    // Ensure the size is enough for extracting parameters
    if (size < sizeof(hoedown_html_flags) + sizeof(int)) {
        return 0;
    }

    // Extract hoedown_html_flags from the input data
    hoedown_html_flags flags = *(const hoedown_html_flags *)data;

    // Extract an integer from the input data
    int render_flags = *(const int *)(data + sizeof(hoedown_html_flags));

    // Call the function-under-test
    hoedown_renderer *renderer = hoedown_html_renderer_new(flags, render_flags);

    // Clean up if necessary
    if (renderer != NULL) {
        hoedown_html_renderer_free(renderer);
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

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
