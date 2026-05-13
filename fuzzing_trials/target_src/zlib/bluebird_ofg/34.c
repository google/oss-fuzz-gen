#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "zlib.h"
#include <stdio.h>  // Include for using printf if needed

// Remove the extern "C" linkage specification for C code
int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    // Ensure that there is enough data to interpret as an off_t value
    if (size < sizeof(off_t)) {
        return 0;
    }

    // Interpret the first bytes of data as an off_t value
    off_t input_off_t = 0;
    for (size_t i = 0; i < sizeof(off_t); ++i) {
        input_off_t = (input_off_t << 8) | data[i];
    }

    // Call the function-under-test
    uLong result = crc32_combine_gen(input_off_t);

    // Use the result in some way to prevent compiler optimizations from removing the call
    // For example, print the result (in real fuzzing, you might not print but use it in some way)
    printf("Result: %lu\n", result); // Print the result for demonstration

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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
