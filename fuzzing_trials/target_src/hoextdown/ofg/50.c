#include <stdint.h>
#include <stddef.h>
#include "/src/hoextdown/src/html.h"

// Function signature for the fuzzer
int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract both parameters
    if (size < sizeof(hoedown_html_flags) + sizeof(int)) {
        return 0;
    }

    // Extract hoedown_html_flags from the input data
    hoedown_html_flags flags = *(const hoedown_html_flags*)(data);

    // Extract int from the input data
    int int_param = *(const int*)(data + sizeof(hoedown_html_flags));

    // Call the function-under-test
    hoedown_renderer *renderer = hoedown_html_renderer_new(flags, int_param);

    // Clean up if necessary (depends on the library's memory management, not shown here)
    // For example, if there is a function to free the renderer, it should be called here.
    // hoedown_renderer_free(renderer); // Uncomment if such a function exists

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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
