#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    const char *path = "/tmp/fuzzed_file";
    FILE *file = fopen(path, "wb");
    if (!file) return 0;
    fwrite(data, 1, size, file);
    fclose(file);

    char *true_path = strdup(path);
    unsigned int access = 0;
    unsigned int group = 0;
    unsigned int offset_size = 0;
    Dwarf_Handler err_handler = NULL;
    Dwarf_Ptr err_arg = NULL;
    Dwarf_Debug *dbg = NULL;
    char **error_msg = NULL;
    unsigned int flags = 0;
    unsigned char *section_data = (unsigned char *)malloc(size);
    memcpy(section_data, data, size);
    Dwarf_Error *error = NULL;

    dwarf_init_path_dl_a(path, true_path, access, group, offset_size, err_handler, err_arg, dbg, error_msg, flags, section_data, error);

    free(true_path);
    free(section_data);

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

    LLVMFuzzerTestOneInput_96(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
