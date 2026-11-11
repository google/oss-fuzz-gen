#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "dwarf.h"
#include "libdwarf.h"

extern int dwarf_dnames_entrypool_values(Dwarf_Dnames_Head head, 
                                         Dwarf_Unsigned index, 
                                         Dwarf_Unsigned offset, 
                                         Dwarf_Unsigned length, 
                                         Dwarf_Half *attrnum, 
                                         Dwarf_Half *formnum, 
                                         Dwarf_Unsigned *val1, 
                                         Dwarf_Sig8 *sig8, 
                                         Dwarf_Bool *is_single, 
                                         Dwarf_Unsigned *val2, 
                                         Dwarf_Unsigned *val3, 
                                         Dwarf_Error *error);

int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Dnames_Head) + 3 * sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    Dwarf_Dnames_Head head = (Dwarf_Dnames_Head)data;
    Dwarf_Unsigned index = (Dwarf_Unsigned)data[sizeof(Dwarf_Dnames_Head)];
    Dwarf_Unsigned offset = (Dwarf_Unsigned)data[sizeof(Dwarf_Dnames_Head) + sizeof(Dwarf_Unsigned)];
    Dwarf_Unsigned length = (Dwarf_Unsigned)data[sizeof(Dwarf_Dnames_Head) + 2 * sizeof(Dwarf_Unsigned)];

    Dwarf_Half attrnum = 0;
    Dwarf_Half formnum = 0;
    Dwarf_Unsigned val1 = 0;
    Dwarf_Sig8 sig8;
    Dwarf_Bool is_single = 0;
    Dwarf_Unsigned val2 = 0;
    Dwarf_Unsigned val3 = 0;
    Dwarf_Error error = NULL;

    int result = dwarf_dnames_entrypool_values(head, index, offset, length, &attrnum, &formnum, &val1, &sig8, &is_single, &val2, &val3, &error);

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

    LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
