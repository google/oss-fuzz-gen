// This fuzz driver is generated for library libdwarf, aiming to fuzz the following functions:
// dwarf_lvn_name at dwarf_lvn_name.c:130:1 in libdwarf.h
// dwarf_lvn_table_entry at dwarf_lvn_name.c:157:1 in libdwarf.h
// dwarf_language_version_data at dwarf_lname_version.c:7:1 in libdwarf.h
// dwarf_srclang at dwarf_query.c:1740:1 in libdwarf.h
#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_141(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Dwarf_Unsigned)) {
        return 0;
    }

    const char *version_name = NULL;
    const char *version_scheme = NULL;
    Dwarf_Unsigned index = *(Dwarf_Unsigned*)Data;
    Data += sizeof(Dwarf_Unsigned);
    Size -= sizeof(Dwarf_Unsigned);

    Dwarf_Die die = NULL; // We cannot create a real Dwarf_Die without a valid context
    int res = dwarf_lvn_name(die, &version_name, &version_scheme);
    if (res == DW_DLV_OK) {
        // Use version_name and version_scheme
    }

    Dwarf_Unsigned language_name;
    Dwarf_Unsigned language_version;
    const char *language_version_scheme = NULL;
    const char *language_version_name = NULL;
    res = dwarf_lvn_table_entry(index, &language_name, &language_version, &language_version_scheme, &language_version_name);
    if (res == DW_DLV_OK) {
        // Use language_name, language_version, language_version_scheme, language_version_name
    }

    int default_lower_bound = 0;
    const char *version_string = NULL;
    res = dwarf_language_version_data(index, &default_lower_bound, &version_string);
    if (res == DW_DLV_OK) {
        // Use default_lower_bound, version_string
    }

    Dwarf_Unsigned returned_lang;
    Dwarf_Error error = NULL;
    res = dwarf_srclang(die, &returned_lang, &error);
    if (res == DW_DLV_OK) {
        // Use returned_lang
    } else if (res == DW_DLV_ERROR) {
        // Handle error
        // Normally you'd use dwarf_dealloc to free the error
    }

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

        LLVMFuzzerTestOneInput_141(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    