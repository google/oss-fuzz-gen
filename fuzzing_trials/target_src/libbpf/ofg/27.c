#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming these types are defined somewhere in the library
typedef int DW_TAG_enumeration_typebpf_prog_type;
typedef int DW_TAG_enumeration_typebpf_attach_type;

// Function-under-test
int libbpf_prog_type_by_name(const char *name, DW_TAG_enumeration_typebpf_prog_type *prog_type, DW_TAG_enumeration_typebpf_attach_type *attach_type);

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated for the string input
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the string and ensure it is null-terminated
    char *name = (char *)malloc(size + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0';

    // Initialize the other parameters
    DW_TAG_enumeration_typebpf_prog_type prog_type = 0;
    DW_TAG_enumeration_typebpf_attach_type attach_type = 0;

    // Call the function-under-test
    libbpf_prog_type_by_name(name, &prog_type, &attach_type);

    // Clean up
    free(name);

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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
