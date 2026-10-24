#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Assuming these are defined somewhere as enums or typedefs
typedef int DW_TAG_enumeration_typebpf_prog_type;
typedef int DW_TAG_enumeration_typebpf_attach_type;

// Assuming this struct is defined somewhere
struct libbpf_prog_handler_opts {
    size_t size;
    // Other fields...
};

// Mock function definition for compilation
int libbpf_register_prog_handler_126(const char *name,
                                 DW_TAG_enumeration_typebpf_prog_type prog_type,
                                 DW_TAG_enumeration_typebpf_attach_type attach_type,
                                 const struct libbpf_prog_handler_opts *opts) {
    // Mock implementation
    return 0;
}

int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    if (size < sizeof(DW_TAG_enumeration_typebpf_prog_type) + sizeof(DW_TAG_enumeration_typebpf_attach_type) + sizeof(struct libbpf_prog_handler_opts)) {
        return 0;
    }

    // Extracting parts of the data for different parameters
    const char *name = "test_prog_handler";  // A non-NULL string
    DW_TAG_enumeration_typebpf_prog_type prog_type = *(DW_TAG_enumeration_typebpf_prog_type *)data;
    data += sizeof(DW_TAG_enumeration_typebpf_prog_type);
    size -= sizeof(DW_TAG_enumeration_typebpf_prog_type);

    DW_TAG_enumeration_typebpf_attach_type attach_type = *(DW_TAG_enumeration_typebpf_attach_type *)data;
    data += sizeof(DW_TAG_enumeration_typebpf_attach_type);
    size -= sizeof(DW_TAG_enumeration_typebpf_attach_type);

    struct libbpf_prog_handler_opts opts;
    memcpy(&opts, data, sizeof(struct libbpf_prog_handler_opts));
    opts.size = sizeof(struct libbpf_prog_handler_opts);  // Ensure size is set correctly

    // Call the function-under-test
    libbpf_register_prog_handler_126(name, prog_type, attach_type, &opts);

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

    LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
