#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    time_t time_input;
    const char *format;
    char *result = NULL;
    LY_ERR err;

    // Ensure the size is sufficient to extract a time_t value
    if (size < sizeof(time_t) + 1) {
        return 0;
    }

    // Extract a time_t value from the input data
    time_input = *(const time_t *)data;

    // Extract a format string from the input data
    format = (const char *)(data + sizeof(time_t));

    // Call the function-under-test
    err = ly_time_time2str(time_input, format, &result);

    // Free allocated memory if necessary
    free(result);

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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
