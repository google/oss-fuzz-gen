// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_is_video_handler_type at isom_read.c:5954:6 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_has_meta_xml at meta.c:52:5 in isomedia.h
// gf_isom_get_edit_list_type at isom_read.c:2504:6 in isomedia.h
// gf_isom_get_tile_info at isom_read.c:5878:6 in isomedia.h
// gf_isom_get_tmcd_config at sample_descs.c:1953:8 in isomedia.h
// gf_isom_is_external_track at isom_read.c:6656:6 in isomedia.h
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

int LLVMFuzzerTestOneInput_97(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    // Test gf_isom_is_video_handler_type
    u32 mtype = *((u32 *)Data);
    Bool is_video = gf_isom_is_video_handler_type(mtype);

    // Prepare a dummy ISO file for other tests
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);

    if (isom_file) {
        // Test gf_isom_has_meta_xml
        Bool root_meta = GF_TRUE;
        u32 track_num = 0;
        u32 has_meta_xml = gf_isom_has_meta_xml(isom_file, root_meta, track_num);

        // Test gf_isom_get_edit_list_type
        s64 mediaOffset = 0;
        Bool edit_list_type = gf_isom_get_edit_list_type(isom_file, track_num, &mediaOffset);

        // Test gf_isom_get_tile_info
        u32 sample_group_description_index = 0;
        u32 default_sample_group_index = 0;
        u32 id = 0, independent = 0, x = 0, y = 0, w = 0, h = 0;
        Bool full_frame = GF_FALSE;
        Bool tile_info = gf_isom_get_tile_info(isom_file, track_num, sample_group_description_index, &default_sample_group_index, &id, &independent, &full_frame, &x, &y, &w, &h);

        // Test gf_isom_get_tmcd_config
        u32 tmcd_flags = 0, tmcd_fps_num = 0, tmcd_fps_den = 0, tmcd_fpt = 0;
        GF_Err tmcd_config_err = gf_isom_get_tmcd_config(isom_file, track_num, sample_group_description_index, &tmcd_flags, &tmcd_fps_num, &tmcd_fps_den, &tmcd_fpt);

        // Test gf_isom_is_external_track
        GF_ISOTrackID tkid = 0;
        u32 type = 0, flags = 0;
        const char *location = NULL;
        Bool is_external = gf_isom_is_external_track(isom_file, track_num, &tkid, &type, &flags, &location);

        // Close the ISO file
        gf_isom_close(isom_file);
    }

    // Write dummy data to a file if needed
    write_dummy_file(Data, Size);

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

        LLVMFuzzerTestOneInput_97(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    