#include <sys/stat.h>
#include "/src/gpac/include/gpac/isomedia.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>  // Include for mkstemp and close

int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    // Initialize variables
    GF_ISOFile *file = gf_isom_open("temp.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!file) return 0;

    Bool root_meta = GF_TRUE;
    u32 track_num = 1;
    Bool self_reference = GF_FALSE;

    // Create a temporary file for resource_path
    char resource_path[] = "/tmp/fuzz_resourceXXXXXX";
    int fd = mkstemp(resource_path);
    if (fd == -1) {
        gf_isom_close(file);
        return 0;
    }
    close(fd);

    const char *item_name = "test_item";
    u32 io_item_id = 0;
    u32 item_type = 1;
    const char *mime_type = "application/octet-stream";
    const char *content_encoding = "identity";
    const char *URL = "http://example.com";
    const char *URN = "urn:example";
    GF_ImageItemProperties image_props = {0};

    // Call the function-under-test
    gf_isom_add_meta_item2(file, root_meta, track_num, self_reference, resource_path, item_name, &io_item_id, item_type, mime_type, content_encoding, URL, URN, &image_props);

    // Clean up
    gf_isom_close(file);
    remove(resource_path);

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

    LLVMFuzzerTestOneInput_96(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
