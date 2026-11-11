#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    GF_ISOFile *file = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!file) return 0;

    Bool root_meta = 1;  // Set to true
    u32 track_num = 1;
    const char *item_name = "test_item";
    u32 item_id_storage = 0;
    u32 *item_id = &item_id_storage;
    u32 item_type = 0;  // Example type
    const char *mime_type = "video/mp4";
    const char *content_encoding = "identity";
    GF_ImageItemProperties image_props;
    memset(&image_props, 0, sizeof(GF_ImageItemProperties));
    u32 tk_id = 1;
    u32 sample_num = 1;

    // Call the function-under-test
    gf_isom_add_meta_item_sample_ref(file, root_meta, track_num, item_name, item_id, item_type, mime_type, content_encoding, &image_props, tk_id, sample_num);

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

    LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
