// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_iff_create_image_identity_item at iff.c:2107:8 in isomedia.h
// gf_isom_start_segment at movie_fragments.c:2515:8 in isomedia.h
// gf_isom_add_meta_item2 at meta.c:1792:8 in isomedia.h
// gf_isom_add_meta_item_memory at meta.c:1800:8 in isomedia.h
// gf_isom_extract_meta_xml at meta.c:68:8 in isomedia.h
// gf_isom_iff_create_image_item_from_track at iff.c:2118:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void initialize_iso_file(GF_ISOFile **isom_file) {
    *isom_file = gf_isom_open(NULL, GF_ISOM_OPEN_WRITE, NULL);
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_61(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = NULL;
    initialize_iso_file(&isom_file);
    if (!isom_file) return 0;

    // Prepare parameters for gf_isom_iff_create_image_identity_item
    Bool root_meta = GF_FALSE;
    u32 meta_track_number = 0;
    const char *item_name = "test_item";
    u32 item_id = 0;
    GF_ImageItemProperties image_props;
    memset(&image_props, 0, sizeof(GF_ImageItemProperties));

    // Fuzz gf_isom_iff_create_image_identity_item
    gf_isom_iff_create_image_identity_item(isom_file, root_meta, meta_track_number, item_name, item_id, &image_props);

    // Prepare parameters for gf_isom_start_segment
    const char *SegName = NULL;
    Bool memory_mode = GF_FALSE;

    // Fuzz gf_isom_start_segment
    gf_isom_start_segment(isom_file, SegName, memory_mode);

    // Prepare parameters for gf_isom_add_meta_item2
    char *resource_path = "./dummy_file";
    u32 io_item_id = 0;
    u32 item_type = 0;
    const char *mime_type = NULL;
    const char *content_encoding = NULL;
    const char *URL = NULL;
    const char *URN = NULL;

    // Fuzz gf_isom_add_meta_item2
    gf_isom_add_meta_item2(isom_file, root_meta, meta_track_number, GF_FALSE, resource_path, item_name, &io_item_id, item_type, mime_type, content_encoding, URL, URN, &image_props);

    // Prepare parameters for gf_isom_add_meta_item_memory
    char *data = (char *)Data;
    u32 data_len = (u32)Size;
    GF_List *item_extent_refs = NULL;

    // Fuzz gf_isom_add_meta_item_memory
    gf_isom_add_meta_item_memory(isom_file, root_meta, meta_track_number, item_name, &item_id, item_type, mime_type, content_encoding, &image_props, data, data_len, item_extent_refs);

    // Prepare parameters for gf_isom_extract_meta_xml
    char *outName = "./dummy_file";
    Bool is_binary = GF_FALSE;

    // Fuzz gf_isom_extract_meta_xml
    gf_isom_extract_meta_xml(isom_file, root_meta, meta_track_number, outName, &is_binary);

    // Prepare parameters for gf_isom_iff_create_image_item_from_track
    u32 media_track = 1;

    // Fuzz gf_isom_iff_create_image_item_from_track
    gf_isom_iff_create_image_item_from_track(isom_file, root_meta, meta_track_number, media_track, item_name, item_id, &image_props, item_extent_refs);

    cleanup_iso_file(isom_file);
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

        LLVMFuzzerTestOneInput_61(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    