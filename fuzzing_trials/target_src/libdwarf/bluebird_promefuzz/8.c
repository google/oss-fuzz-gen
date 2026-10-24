#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "libdwarf.h"

static void fuzz_dwarf_get_LLE_name(unsigned int dw_val_in) {
    const char *name;
    dwarf_get_LLE_name(dw_val_in, &name);
}

static void fuzz_dwarf_get_ID_name(unsigned int dw_val_in) {
    const char *name;
    dwarf_get_ID_name(dw_val_in, &name);
}

static void fuzz_dwarf_get_MACRO_name(unsigned int dw_val_in) {
    const char *name;
    dwarf_get_MACRO_name(dw_val_in, &name);
}

static void fuzz_dwarf_get_ADDR_name(unsigned int dw_val_in) {
    const char *name;
    dwarf_get_ADDR_name(dw_val_in, &name);
}

static void fuzz_dwarf_get_CHILDREN_name(unsigned int dw_val_in) {
    const char *name;
    dwarf_get_CHILDREN_name(dw_val_in, &name);
}

static void fuzz_dwarf_get_DS_name(unsigned int dw_val_in) {
    const char *name;
    dwarf_get_DS_name(dw_val_in, &name);
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) {
        return 0;
    }

    unsigned int dw_val_in = *(unsigned int *)Data;

    fuzz_dwarf_get_LLE_name(dw_val_in);
    fuzz_dwarf_get_ID_name(dw_val_in);
    fuzz_dwarf_get_MACRO_name(dw_val_in);
    fuzz_dwarf_get_ADDR_name(dw_val_in);
    fuzz_dwarf_get_CHILDREN_name(dw_val_in);
    fuzz_dwarf_get_DS_name(dw_val_in);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
