#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/hts.h>
#include <htslib/tbx.h> // Include the header for tabix index functions

int LLVMFuzzerTestOneInput_176(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the function parameters
    if (size < 5) {
        return 0;
    }

    // Extract an integer from the data
    int int_param = (int)data[0];

    // Create a string from the remaining data
    char *str_param = (char *)malloc(size - 1 + 1);
    if (str_param == NULL) {
        return 0;
    }
    memcpy(str_param, data + 1, size - 1);
    str_param[size - 1] = '\0'; // Null-terminate the string

    // Initialize a tbx_t pointer using a function from the library
    tbx_t *tbx = tbx_index_load(str_param);
    if (tbx != NULL) {
        // Use a function that works with tbx_t, like tbx_name2id
        int result = tbx_name2id(tbx, str_param);
        (void)result; // Suppress unused variable warning
    }

    // Clean up
    if (tbx != NULL) {
        tbx_destroy(tbx);
    }
    free(str_param);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_176(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
