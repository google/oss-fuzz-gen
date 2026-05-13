// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_add_meta_item_sample_ref at meta.c:1806:8 in isomedia.h
// gf_isom_iff_create_image_identity_item at iff.c:2107:8 in isomedia.h
// gf_isom_iff_create_image_grid_item at iff.c:1929:8 in isomedia.h
// gf_isom_add_meta_item at meta.c:1784:8 in isomedia.h
// gf_isom_add_meta_item2 at meta.c:1792:8 in isomedia.h
// gf_isom_iff_create_image_overlay_item at iff.c:2063:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

#define DUMMY_FILE_PATH "./dummy_file"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE_PATH, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

static GF_ISOFile* create_dummy_isofile() {
    GF_ISOFile *isom_file = gf_isom_open(DUMMY_FILE_PATH, GF_ISOM_OPEN_WRITE, NULL);
    return isom_file;
}

int LLVMFuzzerTestOneInput_197(const uint8_t *Data, size_t Size) {
    if (Size < 10) return 0; // Ensure we have enough data to avoid overflow

    write_dummy_file(Data, Size);

    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    Bool root_meta = (Bool)(Data[0] % 2);
    u32 track_num = *((u32 *)(Data + 1));
    const char *item_name = "TestItem";
    u32 item_id = 0;
    u32 item_type = *((u32 *)(Data + 5));
    const char *mime_type = "image/jpeg";
    const char *content_encoding = NULL;
    GF_ImageItemProperties *image_props = NULL;
    GF_ISOTrackID tk_id = 1;
    u32 sample_num = 1;

    u32 io_item_id = 0;
    Bool self_reference = (Bool)(Data[9] % 2);

    // Test gf_isom_add_meta_item_sample_ref
    gf_isom_add_meta_item_sample_ref(isom_file, root_meta, track_num, item_name, &item_id, item_type, mime_type, content_encoding, image_props, tk_id, sample_num);

    // Test gf_isom_iff_create_image_identity_item
    gf_isom_iff_create_image_identity_item(isom_file, root_meta, track_num, item_name, item_id, image_props);

    // Test gf_isom_iff_create_image_grid_item
    gf_isom_iff_create_image_grid_item(isom_file, root_meta, track_num, item_name, item_id, image_props);

    // Test gf_isom_add_meta_item
    gf_isom_add_meta_item(isom_file, root_meta, track_num, self_reference, DUMMY_FILE_PATH, item_name, item_id, item_type, mime_type, content_encoding, NULL, NULL, image_props);

    // Test gf_isom_add_meta_item2
    gf_isom_add_meta_item2(isom_file, root_meta, track_num, self_reference, DUMMY_FILE_PATH, item_name, &io_item_id, item_type, mime_type, content_encoding, NULL, NULL, image_props);

    // Test gf_isom_iff_create_image_overlay_item
    gf_isom_iff_create_image_overlay_item(isom_file, root_meta, track_num, item_name, item_id, image_props);

    gf_isom_close(isom_file);
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

        LLVMFuzzerTestOneInput_197(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    