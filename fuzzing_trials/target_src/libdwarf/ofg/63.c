#include <stddef.h>
#include <stdint.h>
#include <dwarf.h>
#include <libdwarf.h>  // Include this to ensure the function prototype is available

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    unsigned int form = *(unsigned int*)data;
    const char *form_name = NULL;

    // Call the function-under-test
    int result = dwarf_get_FORM_name(form, &form_name);

    // Optionally, you can add checks or use the result/form_name
    // to verify the behavior of the function under test.

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

    LLVMFuzzerTestOneInput_63(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
