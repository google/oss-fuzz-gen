#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    GF_ISOFile *file = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!file) {
        return 0;
    }

    Bool root_meta = 1; // Set to true
    u32 track_num = 1; // Initialize with a non-zero value
    u32 item_id = 1; // Initialize with a non-zero value
    u32 group_id = 1; // Initialize with a non-zero value
    u32 group_type = 1; // Initialize with a non-zero value

    // Call the function-under-test
    gf_isom_meta_add_item_group(file, root_meta, track_num, item_id, group_id, group_type);

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

    LLVMFuzzerTestOneInput_130(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
