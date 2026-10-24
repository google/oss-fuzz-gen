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

static const char *get_string_or_default(const char *str) {
    return str ? str : "unknown";
}

int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(unsigned int)) {
        return 0;
    }

    unsigned int dw_val_in = *(unsigned int *)Data;
    const char *dw_s_out = NULL;
    int dw_default_lower_bound = 0;
    const char *dw_version_string = NULL;

    // Fuzz dwarf_get_LANG_name
    if (dwarf_get_LANG_name(dw_val_in, &dw_s_out) == DW_DLV_OK) {
        printf("LANG_name: %s\n", get_string_or_default(dw_s_out));
    }

    // Fuzz dwarf_language_version_string (obsolete)
    if (dwarf_language_version_string(dw_val_in, &dw_default_lower_bound, &dw_version_string) == DW_DLV_OK) {
        printf("LANG_version_string: %s\n", get_string_or_default(dw_version_string));
    }

    // Fuzz dwarf_get_ID_name
    if (dwarf_get_ID_name(dw_val_in, &dw_s_out) == DW_DLV_OK) {
        printf("ID_name: %s\n", get_string_or_default(dw_s_out));
    }

    // Fuzz dwarf_get_LNS_name
    if (dwarf_get_LNS_name(dw_val_in, &dw_s_out) == DW_DLV_OK) {
        printf("LNS_name: %s\n", get_string_or_default(dw_s_out));
    }

    // Fuzz dwarf_get_LNAME_name
    if (dwarf_get_LNAME_name(dw_val_in, &dw_s_out) == DW_DLV_OK) {
        printf("LNAME_name: %s\n", get_string_or_default(dw_s_out));
    }

    // Fuzz dwarf_language_version_data
    if (dwarf_language_version_data(dw_val_in, &dw_default_lower_bound, &dw_version_string) == DW_DLV_OK) {
        printf("LANG_version_data: %s\n", get_string_or_default(dw_version_string));
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
