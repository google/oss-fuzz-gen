#include <stddef.h>
#include <stdint.h>
#include <dwarf.h> // Assuming the function is part of the DWARF library

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    unsigned int access_code;
    const char *access_name = NULL;

    // Ensure the size is at least the size of an unsigned int
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Copy the first sizeof(unsigned int) bytes from data to access_code
    access_code = *(unsigned int *)data;

    // Call the function-under-test
    int result = dwarf_get_ACCESS_name(access_code, &access_name);

    // The function returns an integer, which we can check if needed
    // For fuzzing, we generally don't need to do anything with the result
    // or access_name, just ensure the function is called.

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_101(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
