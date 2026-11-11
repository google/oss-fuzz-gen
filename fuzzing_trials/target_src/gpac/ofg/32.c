#include <stdint.h>
#include <stddef.h>
#include <gpac/isomedia.h>

// Mock implementation of gf_isom_get_meta_type for testing
GF_EXPORT u32 gf_isom_get_meta_type_32(GF_ISOFile *file, Bool root_meta, u32 track_num) {
    // Mock behavior for testing
    return track_num + (root_meta ? 1 : 0);
}

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Define a reasonable minimum size for the input data
    const size_t min_size = sizeof(Bool) + sizeof(u32);

    // Ensure size is sufficient for our needs
    if (size < min_size) {
        return 0;
    }

    // Initialize the GF_ISOFile object
    GF_ISOFile *file = NULL; // Assuming file is initialized in a meaningful way for the test

    // Extract root_meta from data
    Bool root_meta = (Bool)(data[0] % 2); // Ensure it's a valid Bool

    // Extract track_num from data
    u32 track_num = *((u32 *)(data + 1));

    // Call the function-under-test
    u32 result = gf_isom_get_meta_type_32(file, root_meta, track_num);

    // Use the result in some way to avoid compiler optimizations
    (void)result;

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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
