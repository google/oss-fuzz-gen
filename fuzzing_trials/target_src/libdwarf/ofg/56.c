#include <stddef.h>
#include <stdint.h>
#include <libdwarf.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Debug)) {
        return 0; // Not enough data to form a valid Dwarf_Debug
    }

    Dwarf_Debug dbg = (Dwarf_Debug)data;  // Casting data to Dwarf_Debug for testing
    const char *section_name = NULL;
    Dwarf_Error error = NULL;

    // Call the function-under-test
    int result = dwarf_get_ranges_section_name(dbg, &section_name, &error);

    // Normally, you would handle the result and error here, but for fuzzing, we just return.
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

    LLVMFuzzerTestOneInput_56(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
