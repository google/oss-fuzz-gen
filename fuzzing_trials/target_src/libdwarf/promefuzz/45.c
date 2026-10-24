// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_get_OP_name at dwarf_names.c:1564:1 in libdwarf.h
// dwarf_get_ATCF_name at dwarf_names.c:2622:1 in libdwarf.h
// dwarf_get_FORM_name at dwarf_names.c:410:1 in libdwarf.h
// dwarf_get_MACINFO_name at dwarf_names.c:3543:1 in libdwarf.h
// dwarf_get_LNAME_name at dwarf_names.c:2966:1 in libdwarf.h
// dwarf_get_VIS_name at dwarf_names.c:2681:1 in libdwarf.h
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
    
    unsigned int dw_val_in = *(unsigned int*)Data;
    const char *dw_s_out = NULL;
    
    int result = dwarf_get_OP_name(dw_val_in, &dw_s_out);
    if (result == DW_DLV_OK && dw_s_out) {
        // Valid operation name returned, can log or further process if needed
    }
}

static void fuzz_dwarf_get_ATCF_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    
    unsigned int dw_val_in = *(unsigned int*)Data;
    const char *dw_s_out = NULL;
    
    int result = dwarf_get_ATCF_name(dw_val_in, &dw_s_out);
    if (result == DW_DLV_OK && dw_s_out) {
        // Valid ATCF name returned, can log or further process if needed
    }
}

static void fuzz_dwarf_get_FORM_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    
    unsigned int dw_val_in = *(unsigned int*)Data;
    const char *dw_s_out = NULL;
    
    int result = dwarf_get_FORM_name(dw_val_in, &dw_s_out);
    if (result == DW_DLV_OK && dw_s_out) {
        // Valid FORM name returned, can log or further process if needed
    }
}

static void fuzz_dwarf_get_MACINFO_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    
    unsigned int dw_val_in = *(unsigned int*)Data;
    const char *dw_s_out = NULL;
    
    int result = dwarf_get_MACINFO_name(dw_val_in, &dw_s_out);
    if (result == DW_DLV_OK && dw_s_out) {
        // Valid MACINFO name returned, can log or further process if needed
    }
}

static void fuzz_dwarf_get_LNAME_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    
    unsigned int dw_val_in = *(unsigned int*)Data;
    const char *dw_s_out = NULL;
    
    int result = dwarf_get_LNAME_name(dw_val_in, &dw_s_out);
    if (result == DW_DLV_OK && dw_s_out) {
        // Valid LNAME name returned, can log or further process if needed
    }
}

static void fuzz_dwarf_get_VIS_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    
    unsigned int dw_val_in = *(unsigned int*)Data;
    const char *dw_s_out = NULL;
    
    int result = dwarf_get_VIS_name(dw_val_in, &dw_s_out);
    if (result == DW_DLV_OK && dw_s_out) {
        // Valid VIS name returned, can log or further process if needed
    }
}

int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size) {
    fuzz_dwarf_get_OP_name(Data, Size);
    fuzz_dwarf_get_ATCF_name(Data, Size);
    fuzz_dwarf_get_FORM_name(Data, Size);
    fuzz_dwarf_get_MACINFO_name(Data, Size);
    fuzz_dwarf_get_LNAME_name(Data, Size);
    fuzz_dwarf_get_VIS_name(Data, Size);
    
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

        LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    