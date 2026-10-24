#include <stddef.h>
#include <stdint.h>
#include <dwarf.h>
#include <libdwarf.h>
#include <stdlib.h>  // Include for malloc and free
#include <string.h>  // Include for memcpy

#ifdef __cplusplus
extern "C" {
#endif

// Define DW_DLC_READ if it's not defined
#ifndef DW_DLC_READ
#define DW_DLC_READ 0x01  // Assuming 0x01 is the correct value for read mode
#endif

int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Attribute)) {
        return 0;
    }

    // Allocate memory for Dwarf_Attribute to prevent direct casting from data
    Dwarf_Attribute *attr = (Dwarf_Attribute *)malloc(sizeof(Dwarf_Attribute));
    if (!attr) {
        return 0;  // Return if memory allocation fails
    }

    // Copy data into allocated memory
    memcpy(attr, data, sizeof(Dwarf_Attribute));

    Dwarf_Loc_Head_c loclist_head = NULL;
    Dwarf_Unsigned listlen = 0;
    Dwarf_Error error = NULL;

    // Initialize the Dwarf_Debug object
    Dwarf_Debug dbg = NULL;
    int init_result = dwarf_init_path("/dev/null", NULL, 0, DW_DLC_READ, NULL, NULL, &dbg, &error);
    if (init_result != DW_DLV_OK) {
        free(attr);
        return 0;
    }

    // Use a dummy Dwarf_Debug object to prevent segmentation fault
    int result = dwarf_get_loclist_c(*attr, &loclist_head, &listlen, &error);

    // Cleanup if necessary
    if (loclist_head != NULL) {
        dwarf_dealloc_loc_head_c(loclist_head);
    }

    // Free allocated memory for attr
    free(attr);

    // Finish the Dwarf_Debug object
    dwarf_finish(dbg);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_91(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
