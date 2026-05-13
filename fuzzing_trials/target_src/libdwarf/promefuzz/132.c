// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_get_OP_name at dwarf_names.c:1564:1 in libdwarf.h
// dwarf_get_ACCESS_name at dwarf_names.c:2662:1 in libdwarf.h
// dwarf_get_GNUIVIS_name at dwarf_names.c:2463:1 in libdwarf.h
// dwarf_get_VIRTUALITY_name at dwarf_names.c:2700:1 in libdwarf.h
// dwarf_get_END_name at dwarf_names.c:2597:1 in libdwarf.h
// dwarf_get_SECT_name at dwarf_names.c:2538:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>

static void fuzz_dwarf_get_OP_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int dw_val_in = *(unsigned int *)Data;
    const char *dw_s_out = NULL;
    dwarf_get_OP_name(dw_val_in, &dw_s_out);
}

static void fuzz_dwarf_get_ACCESS_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int dw_val_in = *(unsigned int *)Data;
    const char *dw_s_out = NULL;
    dwarf_get_ACCESS_name(dw_val_in, &dw_s_out);
}

static void fuzz_dwarf_get_GNUIVIS_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int dw_val_in = *(unsigned int *)Data;
    const char *dw_s_out = NULL;
    dwarf_get_GNUIVIS_name(dw_val_in, &dw_s_out);
}

static void fuzz_dwarf_get_VIRTUALITY_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int dw_val_in = *(unsigned int *)Data;
    const char *dw_s_out = NULL;
    dwarf_get_VIRTUALITY_name(dw_val_in, &dw_s_out);
}

static void fuzz_dwarf_get_END_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int dw_val_in = *(unsigned int *)Data;
    const char *dw_s_out = NULL;
    dwarf_get_END_name(dw_val_in, &dw_s_out);
}

static void fuzz_dwarf_get_SECT_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int dw_val_in = *(unsigned int *)Data;
    const char *dw_s_out = NULL;
    dwarf_get_SECT_name(dw_val_in, &dw_s_out);
}

int LLVMFuzzerTestOneInput_132(const uint8_t *Data, size_t Size) {
    fuzz_dwarf_get_OP_name(Data, Size);
    fuzz_dwarf_get_ACCESS_name(Data, Size);
    fuzz_dwarf_get_GNUIVIS_name(Data, Size);
    fuzz_dwarf_get_VIRTUALITY_name(Data, Size);
    fuzz_dwarf_get_END_name(Data, Size);
    fuzz_dwarf_get_SECT_name(Data, Size);
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

        LLVMFuzzerTestOneInput_132(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    