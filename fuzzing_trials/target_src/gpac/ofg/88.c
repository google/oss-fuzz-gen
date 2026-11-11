#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
    GF_ISOFile *file = gf_isom_open((const char *)data, GF_ISOM_OPEN_READ, NULL);
    if (!file) {
        return 0;
    }

    // Initialize parameters
    Bool root_meta = GF_FALSE;
    u32 track_num = 1;
    u32 from_id = 1;
    u32 type = 1;
    u32 ref_idx = 1;

    // Call the function-under-test
    gf_isom_meta_get_item_ref_id(file, root_meta, track_num, from_id, type, ref_idx);

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

    LLVMFuzzerTestOneInput_88(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
