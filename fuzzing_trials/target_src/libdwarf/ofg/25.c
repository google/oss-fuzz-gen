#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <dwarf.h>
#include <libdwarf.h>

extern int dwarf_dnames_name(Dwarf_Dnames_Head head, Dwarf_Unsigned index, Dwarf_Unsigned *offset, Dwarf_Unsigned *cu_offset, Dwarf_Unsigned *die_offset, char **name, Dwarf_Unsigned *name_index, Dwarf_Unsigned *hash_index, Dwarf_Half *form, Dwarf_Unsigned section_offset, Dwarf_Half *attr, Dwarf_Half *formclass, Dwarf_Unsigned *attr_offset, Dwarf_Error *error);

int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Unsigned) * 9 + sizeof(Dwarf_Half) * 3 + sizeof(Dwarf_Dnames_Head)) {
        return 0;
    }

    Dwarf_Dnames_Head head = (Dwarf_Dnames_Head)data;
    Dwarf_Unsigned index = *(Dwarf_Unsigned *)(data + sizeof(Dwarf_Dnames_Head));
    Dwarf_Unsigned offset = 0;
    Dwarf_Unsigned cu_offset = 0;
    Dwarf_Unsigned die_offset = 0;
    char *name = NULL;
    Dwarf_Unsigned name_index = 0;
    Dwarf_Unsigned hash_index = 0;
    Dwarf_Half form = 0;
    Dwarf_Unsigned section_offset = *(Dwarf_Unsigned *)(data + sizeof(Dwarf_Dnames_Head) + sizeof(Dwarf_Unsigned));
    Dwarf_Half attr = 0;
    Dwarf_Half formclass = 0;
    Dwarf_Unsigned attr_offset = 0;
    Dwarf_Error error = NULL;

    dwarf_dnames_name(head, index, &offset, &cu_offset, &die_offset, &name, &name_index, &hash_index, &form, section_offset, &attr, &formclass, &attr_offset, &error);

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

    LLVMFuzzerTestOneInput_25(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
