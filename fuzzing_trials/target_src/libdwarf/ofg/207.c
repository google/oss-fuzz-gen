#include <stdint.h>
#include <stddef.h>
#include <dwarf.h>
#include <libdwarf.h>

extern int dwarf_get_locdesc_entry_d(Dwarf_Loc_Head_c, Dwarf_Unsigned, Dwarf_Small *, Dwarf_Unsigned *, Dwarf_Unsigned *, Dwarf_Bool *, Dwarf_Addr *, Dwarf_Addr *, Dwarf_Unsigned *, Dwarf_Locdesc_c *, Dwarf_Small *, Dwarf_Unsigned *, Dwarf_Unsigned *, Dwarf_Error *);

int LLVMFuzzerTestOneInput_207(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Loc_Head_c) + sizeof(Dwarf_Unsigned) * 5 + sizeof(Dwarf_Bool) + sizeof(Dwarf_Addr) * 2) {
        return 0; // Not enough data to fill all parameters
    }

    Dwarf_Loc_Head_c loc_head = (Dwarf_Loc_Head_c)data; // Assuming data can be cast to Dwarf_Loc_Head_c
    Dwarf_Unsigned index = *(const Dwarf_Unsigned *)(data + sizeof(Dwarf_Loc_Head_c));
    Dwarf_Small small_val = *(const Dwarf_Small *)(data + sizeof(Dwarf_Loc_Head_c) + sizeof(Dwarf_Unsigned));
    Dwarf_Unsigned uval1 = *(const Dwarf_Unsigned *)(data + sizeof(Dwarf_Loc_Head_c) + sizeof(Dwarf_Unsigned) + sizeof(Dwarf_Small));
    Dwarf_Unsigned uval2 = *(const Dwarf_Unsigned *)(data + sizeof(Dwarf_Loc_Head_c) + sizeof(Dwarf_Unsigned) * 2 + sizeof(Dwarf_Small));
    Dwarf_Bool bool_val = *(const Dwarf_Bool *)(data + sizeof(Dwarf_Loc_Head_c) + sizeof(Dwarf_Unsigned) * 3 + sizeof(Dwarf_Small));
    Dwarf_Addr addr1 = *(const Dwarf_Addr *)(data + sizeof(Dwarf_Loc_Head_c) + sizeof(Dwarf_Unsigned) * 3 + sizeof(Dwarf_Small) + sizeof(Dwarf_Bool));
    Dwarf_Addr addr2 = *(const Dwarf_Addr *)(data + sizeof(Dwarf_Loc_Head_c) + sizeof(Dwarf_Unsigned) * 3 + sizeof(Dwarf_Small) + sizeof(Dwarf_Bool) + sizeof(Dwarf_Addr));
    Dwarf_Unsigned uval3 = *(const Dwarf_Unsigned *)(data + sizeof(Dwarf_Loc_Head_c) + sizeof(Dwarf_Unsigned) * 3 + sizeof(Dwarf_Small) + sizeof(Dwarf_Bool) + sizeof(Dwarf_Addr) * 2);

    Dwarf_Locdesc_c locdesc = NULL;
    Dwarf_Small small_out = 0;
    Dwarf_Unsigned uval_out1 = 0;
    Dwarf_Unsigned uval_out2 = 0;
    Dwarf_Error error = NULL;

    dwarf_get_locdesc_entry_d(loc_head, index, &small_val, &uval1, &uval2, &bool_val, &addr1, &addr2, &uval3, &locdesc, &small_out, &uval_out1, &uval_out2, &error);

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

    LLVMFuzzerTestOneInput_207(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
