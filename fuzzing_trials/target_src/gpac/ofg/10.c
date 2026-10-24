#include <gpac/isomedia.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Initialize variables
    GF_ISOFile *file = gf_isom_open(NULL, GF_ISOM_WRITE_EDIT, NULL);
    if (!file) return 0;

    Bool root_meta = true;
    u32 track_num = 1;
    Bool self_reference = false;
    char resource_path[] = "/tmp/resource";
    char item_name[] = "test_item";
    u32 io_item_id = 0;
    u32 item_type = 1;
    char mime_type[] = "text/plain";
    char content_encoding[] = "utf-8";
    char URL[] = "http://example.com";
    char URN[] = "urn:example";
    GF_ImageItemProperties image_props = {0};

    // Use the input data to modify the behavior of the function under test
    if (size > 0) {
        track_num = data[0]; // Example of using input data
    }

    // Call the function under test
    gf_isom_add_meta_item2(file, root_meta, track_num, self_reference, resource_path, item_name, &io_item_id, item_type,
                           mime_type, content_encoding, URL, URN, &image_props);

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
