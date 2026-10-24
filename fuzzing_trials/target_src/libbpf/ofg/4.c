#include <stdint.h>
#include <stddef.h>

// Assuming the enumeration type is defined as follows
typedef enum {
    LIBBPF_STRICT_ALL = 0,
    LIBBPF_STRICT_NONE = 1,
    LIBBPF_STRICT_CUSTOM = 2
} DW_TAG_enumeration_typelibbpf_strict_mode;

// Function prototype for the function-under-test
int libbpf_set_strict_mode(DW_TAG_enumeration_typelibbpf_strict_mode mode);

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Ensure that the size is valid to extract an enumeration value
    if (size < 1) {
        return 0;
    }

    // Extract the first byte to use as the mode for the function
    uint8_t mode_byte = data[0];
    DW_TAG_enumeration_typelibbpf_strict_mode mode;

    // Map the byte to a valid enumeration value
    switch (mode_byte % 3) {
        case 0:
            mode = LIBBPF_STRICT_ALL;
            break;
        case 1:
            mode = LIBBPF_STRICT_NONE;
            break;
        case 2:
            mode = LIBBPF_STRICT_CUSTOM;
            break;
    }

    // Call the function-under-test with the fuzzed mode
    libbpf_set_strict_mode(mode);

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
