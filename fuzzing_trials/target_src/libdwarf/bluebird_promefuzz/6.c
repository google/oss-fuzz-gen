#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "libdwarf.h"

static void fuzz_dwarf_get_ISA_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int dw_val_in = *(unsigned int *)Data;
    const char *dw_s_out = NULL;
    dwarf_get_ISA_name(dw_val_in, &dw_s_out);
}

static void fuzz_dwarf_get_FORM_CLASS_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(enum Dwarf_Form_Class)) return;
    enum Dwarf_Form_Class dw_fc = *(enum Dwarf_Form_Class *)Data;
    const char *dw_s_out = NULL;
    dwarf_get_FORM_CLASS_name(dw_fc, &dw_s_out);
}

static void fuzz_dwarf_get_GNUIVIS_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int dw_val_in = *(unsigned int *)Data;
    const char *dw_s_out = NULL;
    dwarf_get_GNUIVIS_name(dw_val_in, &dw_s_out);
}

static void fuzz_dwarf_get_CC_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int dw_val_in = *(unsigned int *)Data;
    const char *dw_s_out = NULL;
    dwarf_get_CC_name(dw_val_in, &dw_s_out);
}

static void fuzz_dwarf_get_IDX_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int dw_val_in = *(unsigned int *)Data;
    const char *dw_s_out = NULL;
    dwarf_get_IDX_name(dw_val_in, &dw_s_out);
}

static void fuzz_dwarf_get_GNUIKIND_name(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) return;
    unsigned int dw_val_in = *(unsigned int *)Data;
    const char *dw_s_out = NULL;
    dwarf_get_GNUIKIND_name(dw_val_in, &dw_s_out);
}

int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    fuzz_dwarf_get_ISA_name(Data, Size);
    fuzz_dwarf_get_FORM_CLASS_name(Data, Size);
    fuzz_dwarf_get_GNUIVIS_name(Data, Size);
    fuzz_dwarf_get_CC_name(Data, Size);
    fuzz_dwarf_get_IDX_name(Data, Size);
    fuzz_dwarf_get_GNUIKIND_name(Data, Size);
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
