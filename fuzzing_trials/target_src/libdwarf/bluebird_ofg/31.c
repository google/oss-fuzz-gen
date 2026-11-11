#include <sys/stat.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Assuming the function is defined in a library we are linking against
extern int dwarf_get_UT_name(unsigned int ut, const char **name);

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read an unsigned int
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Extract an unsigned int from the input data
    unsigned int ut = *(unsigned int *)data;

    // Prepare a non-NULL pointer for the output parameter
    const char *name = NULL;

    // Call the function-under-test
    int result = dwarf_get_UT_name(ut, &name);

    // Optionally, print the result and name for debugging purposes
    if (result == 0 && name != NULL) {
        printf("UT: %u, Name: %s\n", ut, name);
    } else {
        printf("UT: %u, Result: %d\n", ut, result);
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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
