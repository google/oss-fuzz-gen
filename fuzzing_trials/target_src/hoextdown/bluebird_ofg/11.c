#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "html.h"  // Corrected path for the header file

// Include the necessary header for hoedown_renderer_free
#include "document.h" // Assuming this is where hoedown_renderer_free is declared

int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int input_option = *((int*)data);

    // Call the function-under-test
    hoedown_renderer *renderer = hoedown_html_toc_renderer_new(input_option);

    // Clean up if necessary
    if (renderer != NULL) {
        // Correctly use the function to free the renderer
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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
