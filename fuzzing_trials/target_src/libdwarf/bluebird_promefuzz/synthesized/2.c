#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "libdwarf.h"

static void fuzz_dwarf_get_DSC_name(unsigned int value) {
    const char* name;
    dwarf_get_DSC_name(value, &name);
}

static void fuzz_dwarf_get_ACCESS_name(unsigned int value) {
    const char* name;
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function dwarf_get_ACCESS_name with dwarf_get_SECT_name
    dwarf_get_SECT_name(value, &name);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
}

static void fuzz_dwarf_get_EH_name(unsigned int value) {
    const char* name;
    dwarf_get_EH_name(value, &name);
}

static void fuzz_dwarf_get_AT_name(unsigned int value) {
    const char* name;
    dwarf_get_AT_name(value, &name);
}

static void fuzz_dwarf_get_FRAME_name(unsigned int value) {
    const char* name;
    dwarf_get_FRAME_name(value, &name);
}

static void fuzz_dwarf_get_UT_name(unsigned int value) {
    const char* name;
    dwarf_get_UT_name(value, &name);
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) {
        return 0;
    }

    unsigned int value;
    memcpy(&value, Data, sizeof(unsigned int));

    fuzz_dwarf_get_DSC_name(value);
    fuzz_dwarf_get_ACCESS_name(value);
    fuzz_dwarf_get_EH_name(value);
    fuzz_dwarf_get_AT_name(value);
    fuzz_dwarf_get_FRAME_name(value);
    fuzz_dwarf_get_UT_name(value);

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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
