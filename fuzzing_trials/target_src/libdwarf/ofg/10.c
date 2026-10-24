#include <stddef.h>
#include <stdint.h>

// Assume the function is declared in some included header file
// int dwarf_get_UT_name(unsigned int, const char **);

extern int dwarf_get_UT_name(unsigned int, const char **);

int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    unsigned int ut_value = *(unsigned int *)data;
    const char *name = NULL;

    // Call the function-under-test
    int result = dwarf_get_UT_name(ut_value, &name);

    // Use the result and name in some way to avoid unused variable warnings
    (void)result;
    if (name != NULL) {
        // Optionally, you can do something with 'name' here
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

    LLVMFuzzerTestOneInput_10(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
