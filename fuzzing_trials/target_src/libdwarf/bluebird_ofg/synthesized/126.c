#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "libdwarf.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the required structures
    if (size < sizeof(Dwarf_Sig8) + 1) {
        return 0;
    }

    // Initialize Dwarf_Debug
    Dwarf_Debug dbg = (Dwarf_Debug)(uintptr_t)data; // Casting data to a pointer type

    // Initialize Dwarf_Sig8
    Dwarf_Sig8 sig8;
    memcpy(&sig8, data, sizeof(Dwarf_Sig8));

    // Initialize a non-NULL string
    const char *str = (const char *)(data + sizeof(Dwarf_Sig8));

    // Initialize Dwarf_Die
    Dwarf_Die die = (Dwarf_Die)(uintptr_t)(data + sizeof(Dwarf_Sig8) + 1);

    // Initialize Dwarf_Error
    Dwarf_Error err = NULL;

    // Call the function-under-test
    int result = dwarf_die_from_hash_signature(dbg, &sig8, str, &die, &err);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
