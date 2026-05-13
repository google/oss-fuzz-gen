#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for the parameters
    if (size < sizeof(u32) * 4 + sizeof(Bool) + sizeof(u64)) {
        return 0;
    }

    // Initialize the parameters
    GF_ISOFile *file = gf_isom_open(NULL, GF_ISOM_OPEN_WRITE, NULL);
    if (!file) {
        return 0;
    }

    Bool root_meta = (Bool)data[0]; // Extract a Bool value from the data
    u32 track_num = *((u32 *)(data + 1)); // Extract a u32 value for track_num
    u32 from_id = *((u32 *)(data + 5)); // Extract a u32 value for from_id
    u32 to_id = *((u32 *)(data + 9)); // Extract a u32 value for to_id
    u32 type = *((u32 *)(data + 13)); // Extract a u32 value for type
    u64 ref_index = 0; // Initialize ref_index

    // Call the function-under-test
    gf_isom_meta_add_item_ref(file, root_meta, track_num, from_id, to_id, type, &ref_index);

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

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
