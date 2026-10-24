#include <stddef.h>
#include <stdint.h>
#include <dwarf.h>
#include <libdwarf.h> // Include the necessary header for dwarf_get_AT_name

int LLVMFuzzerTestOneInput_252(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to extract an unsigned int
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Extract an unsigned int from the input data
    unsigned int attr = *(const unsigned int *)data;

    // Define a pointer for the attribute name
    const char *attr_name = NULL;

    // Call the function-under-test
    int result = dwarf_get_AT_name(attr, &attr_name);

    // Optionally, you can check the result or use attr_name for further processing
    // For fuzzing purposes, we just ensure the function is called

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

    LLVMFuzzerTestOneInput_252(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
