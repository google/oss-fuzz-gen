#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>  // Include the GPAC isomedia header for GF_ISOFile and related types
#include <gpac/constants.h> // Include GPAC constants header for file open modes

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract parameters
    if (size < sizeof(uint32_t) * 4 + sizeof(Bool)) {
        return 0;
    }

    // Initialize a GF_ISOFile using the appropriate GPAC function
    GF_ISOFile *file = gf_isom_open(NULL, GF_ISOM_OPEN_EDIT, NULL); // Use GF_ISOM_OPEN_EDIT for read-write access
    if (file == NULL) {
        return 0; // Exit if file initialization fails
    }

    // Extract parameters from the input data
    Bool root_meta = (Bool)data[0];
    u32 track_num = *((u32 *)(data + 1));
    u32 item_id = *((u32 *)(data + 1 + sizeof(u32)));
    u32 group_id = *((u32 *)(data + 1 + 2 * sizeof(u32)));
    u32 group_type = *((u32 *)(data + 1 + 3 * sizeof(u32)));

    // Call the function-under-test
    gf_isom_meta_add_item_group(file, root_meta, track_num, item_id, group_id, group_type);

    // Clean up allocated resources
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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
