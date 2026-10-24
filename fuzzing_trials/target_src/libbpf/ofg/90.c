#include <stdint.h>
#include <linux/types.h>
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    // Call the function-under-test
    __u32 version = libbpf_major_version();

    // Use the version in some way to avoid compiler optimizations removing the call
    if (version == 0) {
        return 0;
    }

    // Utilize the input data in some way to maximize fuzzing result
    if (size > 0 && data != NULL) {
        // Example of using the input data
        __u32 input_value = data[0]; // Use the first byte of data

        // Use more of the input data to increase code coverage
        for (size_t i = 0; i < size; i++) {
            input_value ^= data[i]; // XOR all bytes to create a more complex input value
        }

        // Compare the complex input value with the version
        if (input_value == version) {
            return 1;
        }
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

    LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
