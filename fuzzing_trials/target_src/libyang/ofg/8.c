#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Declare and initialize the parameters for ly_time_time2str
    time_t time_value;
    const char *format = "%Y-%m-%dT%H:%M:%S%z";
    char *result_str = NULL;

    // Ensure size is sufficient to extract a time_t value
    if (size < sizeof(time_t)) {
        return 0;
    }

    // Copy data into time_value
    memcpy(&time_value, data, sizeof(time_t));

    // Call the function-under-test
    LY_ERR err = ly_time_time2str(time_value, format, &result_str);

    // Free the allocated string if it was successfully created
    if (err == LY_SUCCESS && result_str) {
        free(result_str);
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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
