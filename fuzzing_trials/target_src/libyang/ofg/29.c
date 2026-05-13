#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>  // Include for uint8_t
#include "libyang.h"

int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the input string and ensure it is null-terminated
    char *input_str = (char *)malloc(size + 1);
    if (!input_str) {
        return 0;
    }
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    time_t time_val;
    char *time_zone = NULL;

    // Check if the input string is a valid time string
    if (strptime(input_str, "%Y-%m-%dT%H:%M:%S", NULL) == NULL) {
        // If the input string is not a valid time format, skip processing
        free(input_str);
        return 0;
    }

    // Call the function-under-test
    LY_ERR result = ly_time_str2time(input_str, &time_val, &time_zone);

    // Check the result and handle accordingly
    if (result == LY_SUCCESS) {
        printf("Converted time: %ld, Time zone: %s\n", time_val, time_zone ? time_zone : "None");
    } else {
        printf("Failed to convert time string: %s\n", input_str);
    }

    // Free allocated memory
    free(input_str);
    if (time_zone) {
        free(time_zone);
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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
