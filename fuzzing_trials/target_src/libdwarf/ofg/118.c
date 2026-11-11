#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Function prototype for the function-under-test
int dwarf_get_GNUIKIND_name(unsigned int kind, const char **name);

// Fuzzer entry point
int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read an unsigned int
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Extract an unsigned int from the input data
    unsigned int kind = *(unsigned int *)data;

    // Declare a pointer for the name
    const char *name = NULL;

    // Call the function-under-test
    int result = dwarf_get_GNUIKIND_name(kind, &name);

    // Optionally, you can add checks or further processing here
    // For example, you can check the result or use the name

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

    LLVMFuzzerTestOneInput_118(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
