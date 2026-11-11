#include <stdint.h>
#include <stddef.h>
#include <libdwarf.h>
#include <dwarf.h>
#include <stdlib.h>
#include <stdio.h>

// Define DW_DLC_READ if it's not defined
#ifndef DW_DLC_READ
#define DW_DLC_READ 0x01  // Typical value for DW_DLC_READ, adjust if necessary
#endif

extern int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Half)) {
        return 0;
    }

    Dwarf_Debug dbg;
    Dwarf_Error error;
    int res = dwarf_init_path("/dev/null", NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &error);
    if (res != DW_DLV_OK) {
        fprintf(stderr, "Failed to initialize Dwarf_Debug\n");
        return 0;
    }

    Dwarf_Half value = *(Dwarf_Half *)data;  // Use the first bytes as Dwarf_Half

    // Call the function-under-test
    Dwarf_Half result = dwarf_set_frame_rule_initial_value(dbg, value);

    // Use the result in some way to avoid compiler optimizations
    volatile Dwarf_Half use_result = result;
    (void)use_result;

    // Clean up
    dwarf_finish(dbg);

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

    LLVMFuzzerTestOneInput_53(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
