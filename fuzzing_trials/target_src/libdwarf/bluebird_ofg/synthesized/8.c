#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "dwarf.h"
#include "libdwarf.h"
#include <string.h>

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    const char *path = "/tmp/fuzzfile";
    char *true_path_out = (char *)malloc(256);
    if (!true_path_out) {
        return 0;
    }
    unsigned int access = 0;
    unsigned int groupnumber = 0;
    Dwarf_Handler errhand = NULL;
    Dwarf_Ptr errarg = NULL;
    Dwarf_Debug dbg;
    char **error = (char **)malloc(sizeof(char *));
    if (!error) {
        free(true_path_out);
        return 0;
    }
    unsigned int interface_number = 0;
    unsigned char *section_pointer = (unsigned char *)malloc(256);
    if (!section_pointer) {
        free(true_path_out);
        free(error);
        return 0;
    }
    Dwarf_Error err;

    // Use fuzzing input data to simulate realistic input
    if (size > 0) {
        access = data[0];
    }
    if (size > 1) {
        groupnumber = data[1];
    }
    if (size > 2) {
        interface_number = data[2];
    }
    if (size > 3) {
        memcpy(section_pointer, data + 3, size - 3 < 256 ? size - 3 : 256);
    }

    // Call the function-under-test
    dwarf_init_path_dl(path, true_path_out, access, groupnumber, errhand, errarg, &dbg, error, interface_number, section_pointer, &err);

    // Clean up
    free(true_path_out);
    free(error);
    free(section_pointer);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
