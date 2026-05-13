#include <stdint.h>
#include <stddef.h>
#include <gpac/isomedia.h>

// Define the LLVMFuzzerTestOneInput function without the 'extern "C"' declaration
int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract required parameters
    if (size < sizeof(u32) * 3 + 2) {
        return 0;
    }

    // Initialize parameters for gf_isom_remove_meta_item
    GF_ISOFile *file = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_READ, NULL); // Assuming a dummy file for fuzzing
    if (!file) {
        return 0;
    }

    // Extract parameters from data
    Bool root_meta = (Bool)data[0]; // First byte for root_meta
    u32 track_num = *((u32 *)(data + 1)); // Next 4 bytes for track_num
    u32 item_id = *((u32 *)(data + 5)); // Next 4 bytes for item_id
    Bool keep_refs = (Bool)data[9]; // Next byte for keep_refs

    // Remaining data for keep_props
    const char *keep_props = (const char *)(data + 10);

    // Call the function-under-test
    gf_isom_remove_meta_item(file, root_meta, track_num, item_id, keep_refs, keep_props);

    // Clean up
    gf_isom_close(file);

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

    LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
