#include <stdint.h>
#include <stdlib.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_184(const uint8_t *data, size_t size) {
    Dwarf_Debug dbg = 0; // Initialize Dwarf_Debug to 0 or NULL
    Dwarf_Half table_size;

    if (size < sizeof(Dwarf_Half)) {
        return 0; // Not enough data to extract a Dwarf_Half value
    }

    // Extract a Dwarf_Half value from the data
    table_size = *(Dwarf_Half *)data;

    // Call the function-under-test
    dwarf_set_frame_rule_table_size(dbg, table_size);

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

    LLVMFuzzerTestOneInput_184(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
