#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int dwarf_get_ATE_name(unsigned int ate, const char **name);

int LLVMFuzzerTestOneInput_109(const uint8_t *data, size_t size) {
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    unsigned int ate;
    const char *name = NULL;

    // Copy the first bytes of data into ate
    ate = *(unsigned int *)data;

    // Call the function-under-test
    int result = dwarf_get_ATE_name(ate, &name);

    // Optionally print the result and name for debugging
    if (name != NULL) {
        printf("Result: %d, Name: %s\n", result, name);
    } else {
        printf("Result: %d, Name: NULL\n", result);
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

    LLVMFuzzerTestOneInput_109(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
