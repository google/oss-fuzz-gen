#include <stdint.h>
#include <stdio.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    GF_ISOFile *file = gf_isom_open("temp.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!file) {
        return 0;
    }

    // Ensure we have enough data to extract track_num and item_id
    if (size < 8) {
        gf_isom_close(file);
        return 0;
    }

    // Extract track_num and item_id from the input data
    u32 track_num = *((u32 *)data);
    u32 item_id = *((u32 *)(data + 4));

    // Set root_meta to true or false based on the first byte of data
    Bool root_meta = (data[0] % 2 == 0) ? GF_TRUE : GF_FALSE;

    // Call the function-under-test
    gf_isom_set_meta_primary_item(file, root_meta, track_num, item_id);

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

    LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
