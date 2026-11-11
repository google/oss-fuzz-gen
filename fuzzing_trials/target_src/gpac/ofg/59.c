#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    GF_ISOFile *file = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (file == NULL) {
        return 0;
    }

    Bool root_meta = true; // or false, to test both possibilities
    u32 track_num = size > 0 ? data[0] : 1; // Use first byte of data or default to 1
    u32 from_id = size > 1 ? data[1] : 1; // Use second byte of data or default to 1
    u32 to_id = size > 2 ? data[2] : 1; // Use third byte of data or default to 1
    u32 type = size > 3 ? data[3] : 1; // Use fourth byte of data or default to 1
    u64 ref_index = 0;

    gf_isom_meta_add_item_ref(file, root_meta, track_num, from_id, to_id, type, &ref_index);

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

    LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
