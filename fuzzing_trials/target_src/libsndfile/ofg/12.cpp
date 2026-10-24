#include <stdint.h>
#include <stddef.h>

// Assuming the function is part of a C library
extern "C" {
    const char * sf_error_number(int);
}

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    // Ensure size is at least the size of an int
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an int from the input data
    int error_number = *(reinterpret_cast<const int*>(data));

    // Call the function-under-test
    const char *error_message = sf_error_number(error_number);

    // Use the error_message in some way to avoid compiler optimization issues
    if (error_message) {
        // Just a dummy operation to use the error_message
        volatile char first_char = error_message[0];
        (void)first_char;
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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
