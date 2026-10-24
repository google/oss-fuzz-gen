#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Initialize variables
    GF_ISOFile *file = gf_isom_open("temp.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!file) return 0;

    Bool root_meta = 1;  // Use true for root_meta
    u32 track_num = 1;   // Example track number
    const char *item_name = "test_item";
    u32 item_id_value = 0;
    u32 *item_id = &item_id_value;
    u32 item_type = GF_ISOM_BOX_TYPE_SENC;  // Use the suggested item type
    const char *mime_type = "video/mp4";
    const char *content_encoding = "identity";
    GF_ImageItemProperties image_props = {0};  // Initialize to zero
    char *data_copy = (char *)malloc(size);
    if (!data_copy) {
        gf_isom_close(file);
        return 0;
    }
    memcpy(data_copy, data, size);
    u32 data_len = (u32)size;
    GF_List *item_extent_refs = gf_list_new();

    // Call the function-under-test
    gf_isom_add_meta_item_memory(file, root_meta, track_num, item_name, item_id, item_type, mime_type, content_encoding, &image_props, data_copy, data_len, item_extent_refs);

    // Clean up
    free(data_copy);
    gf_list_del(item_extent_refs);
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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
