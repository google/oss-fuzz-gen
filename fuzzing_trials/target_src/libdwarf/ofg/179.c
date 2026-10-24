#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Assuming the function is declared in some header file
int dwarf_get_GNUIVIS_name(unsigned int, const char **);

int LLVMFuzzerTestOneInput_179(const uint8_t *data, size_t size) {
    // Ensure there's enough data to form an unsigned int
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Extract an unsigned int from the input data
    unsigned int input_value = *(unsigned int *)data;

    // Initialize a pointer for the output string
    const char *output_name = NULL;

    // Call the function-under-test
    int result = dwarf_get_GNUIVIS_name(input_value, &output_name);

    // Optionally, you can perform some checks or operations on output_name
    // For example, if output_name is expected to be a valid string, you can check it
    if (output_name != NULL) {
        // Perform operations on output_name if needed
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_179(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
