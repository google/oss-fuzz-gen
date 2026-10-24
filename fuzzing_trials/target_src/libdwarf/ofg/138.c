#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int dwarf_get_children_name(unsigned int, const char **);

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    unsigned int param1;
    const char *param2;

    if (size < sizeof(unsigned int) + 1) {
        return 0;
    }

    // Initialize param1 from the input data
    param1 = *((unsigned int*)data);

    // Initialize param2 to point to the rest of the data
    param2 = (const char*)(data + sizeof(unsigned int));

    // Ensure param2 is null-terminated by creating a copy
    char *param2_copy = (char *)malloc(size - sizeof(unsigned int) + 1);
    if (param2_copy == NULL) {
        return 0;
    }
    memcpy(param2_copy, param2, size - sizeof(unsigned int));
    param2_copy[size - sizeof(unsigned int)] = '\0';

    // Call the function-under-test
    dwarf_get_children_name(param1, (const char **)&param2_copy);

    // Free the allocated memory
    free(param2_copy);

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

    LLVMFuzzerTestOneInput_138(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
