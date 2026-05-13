#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
    // Initialize variables required for the function call
    GF_ISOFile *file = gf_isom_open("test.mp4", GF_ISOM_OPEN_READ, NULL); // Open a sample ISO file
    if (!file) {
        return 0; // Return if the file cannot be opened
    }

    // Ensure that the data size is sufficient to extract required parameters
    if (size < sizeof(Bool) + 2 * sizeof(u32)) {
        gf_isom_close(file);
        return 0;
    }

    // Extract parameters from the input data
    Bool root_meta = (Bool)data[0];
    u32 track_num = *((u32 *)(data + 1));
    u32 item_ID = *((u32 *)(data + 1 + sizeof(u32)));

    // Call the function-under-test
    gf_isom_get_meta_item_by_id(file, root_meta, track_num, item_ID);

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

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
