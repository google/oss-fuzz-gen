// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_add_meta_item_sample_ref at meta.c:1806:8 in isomedia.h
// gf_isom_get_meta_image_props at meta.c:735:8 in isomedia.h
// gf_isom_iff_create_image_grid_item at iff.c:1929:8 in isomedia.h
// gf_isom_add_meta_item_memory at meta.c:1800:8 in isomedia.h
// gf_isom_iff_create_image_overlay_item at iff.c:2063:8 in isomedia.h
// gf_isom_iff_create_image_item_from_track at iff.c:2118:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

static GF_ImageItemProperties* create_image_props() {
    GF_ImageItemProperties *image_props = (GF_ImageItemProperties*)malloc(sizeof(GF_ImageItemProperties));
    if (image_props) {
        // Initialize image_props with default or safe values
        image_props->num_grid_rows = 1;
        image_props->num_grid_columns = 1;
    }
    return image_props;
}

int LLVMFuzzerTestOneInput_141(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0; // Ensure there is enough data to access Data[1]

    // Prepare necessary variables
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!isom_file) return 0;

    Bool root_meta = Data[0] % 2;
    u32 track_num = Data[1];
    const char *item_name = "item_name";
    u32 item_id = 0;
    u32 item_type = 0x12345678; // Example four character code
    const char *mime_type = "video/mp4";
    const char *content_encoding = "utf-8";
    GF_ImageItemProperties *image_props = create_image_props();
    GF_ISOTrackID tk_id = 0;
    u32 sample_num = 1;

    // Write dummy data to file
    write_dummy_file(Data, Size);

    // Fuzz gf_isom_add_meta_item_sample_ref
    gf_isom_add_meta_item_sample_ref(isom_file, root_meta, track_num, item_name, &item_id, item_type, mime_type, content_encoding, image_props, tk_id, sample_num);

    // Fuzz gf_isom_get_meta_image_props
    GF_ImageItemProperties out_image_props;
    GF_List *unmapped_props = NULL;
    gf_isom_get_meta_image_props(isom_file, root_meta, track_num, item_id, &out_image_props, unmapped_props);

    // Fuzz gf_isom_iff_create_image_grid_item
    gf_isom_iff_create_image_grid_item(isom_file, root_meta, track_num, item_name, item_id, image_props);

    // Fuzz gf_isom_add_meta_item_memory
    char *data = (char *)malloc(Size);
    if (data) {
        memcpy(data, Data, Size);
        gf_isom_add_meta_item_memory(isom_file, root_meta, track_num, item_name, &item_id, item_type, mime_type, content_encoding, image_props, data, Size, unmapped_props);
        free(data);
    }

    // Fuzz gf_isom_iff_create_image_overlay_item
    gf_isom_iff_create_image_overlay_item(isom_file, root_meta, track_num, item_name, item_id, image_props);

    // Fuzz gf_isom_iff_create_image_item_from_track
    u32 media_track = 1;
    gf_isom_iff_create_image_item_from_track(isom_file, root_meta, track_num, media_track, item_name, item_id, image_props, unmapped_props);

    // Cleanup
    free(image_props);
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

        LLVMFuzzerTestOneInput_141(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    