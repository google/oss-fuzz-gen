// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_formexprloc at dwarf_form.c:2286:1 in libdwarf.h
// dwarf_global_formref_b at dwarf_form.c:748:1 in libdwarf.h
// dwarf_convert_to_global_offset at dwarf_form.c:338:1 in libdwarf.h
// dwarf_formflag at dwarf_form.c:1374:1 in libdwarf.h
// dwarf_formref at dwarf_form.c:463:1 in libdwarf.h
// dwarf_formaddr at dwarf_form.c:1317:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "libdwarf.h"

static Dwarf_Attribute create_dummy_attribute() {
    // We cannot directly allocate a Dwarf_Attribute because its structure is opaque
    return NULL;
}

int LLVMFuzzerTestOneInput_106(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    Dwarf_Attribute attr = create_dummy_attribute();
    Dwarf_Unsigned exprlen = 0;
    Dwarf_Ptr block_ptr = NULL;
    Dwarf_Error error = NULL;

    // Fuzz dwarf_formexprloc
    dwarf_formexprloc(attr, &exprlen, &block_ptr, &error);

    Dwarf_Off offset = 0;
    Dwarf_Bool is_info = 0;

    // Fuzz dwarf_global_formref_b
    dwarf_global_formref_b(attr, &offset, &is_info, &error);

    Dwarf_Off return_offset = 0;

    // Fuzz dwarf_convert_to_global_offset
    dwarf_convert_to_global_offset(attr, offset, &return_offset, &error);

    Dwarf_Bool returned_bool = 0;

    // Fuzz dwarf_formflag
    dwarf_formflag(attr, &returned_bool, &error);

    // Fuzz dwarf_formref
    dwarf_formref(attr, &offset, &is_info, &error);

    Dwarf_Addr returned_addr = 0;

    // Fuzz dwarf_formaddr
    dwarf_formaddr(attr, &returned_addr, &error);

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

        LLVMFuzzerTestOneInput_106(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    