// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_get_rvc_config at isom_read.c:4936:8 in isomedia.h
// gf_isom_set_rvc_config at isom_write.c:7065:8 in isomedia.h
// gf_isom_get_cenc_info at drm_sample.c:726:8 in isomedia.h
// gf_isom_update_bitrate at sample_descs.c:1776:8 in isomedia.h
// gf_isom_update_video_sample_entry_fields at isom_write.c:8557:8 in isomedia.h
// gf_isom_truehd_config_new at sample_descs.c:436:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Create a dummy ISO file structure for testing
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return iso_file;
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    // Write the input data to a dummy file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = 1;
    u32 sampleDescriptionIndex = 1;
    u16 rvc_predefined = 0;
    u8 *data = NULL;
    u32 size = 0;
    const char *mime = NULL;

    gf_isom_get_rvc_config(iso_file, trackNumber, sampleDescriptionIndex, &rvc_predefined, &data, &size, &mime);

    u16 set_rvc_predefined = (Size > 0) ? Data[0] : 0;
    char *set_mime = "video/mp4";
    u8 *set_data = (u8 *)Data;
    u32 set_size = (u32)Size;

    gf_isom_set_rvc_config(iso_file, trackNumber, sampleDescriptionIndex, set_rvc_predefined, set_mime, set_data, set_size);

    u32 outOriginalFormat = 0;
    u32 outSchemeType = 0;
    u32 outSchemeVersion = 0;

    gf_isom_get_cenc_info(iso_file, trackNumber, sampleDescriptionIndex, &outOriginalFormat, &outSchemeType, &outSchemeVersion);

    u32 average_bitrate = (Size > 4) ? *(u32 *)(Data + 1) : 0;
    u32 max_bitrate = (Size > 8) ? *(u32 *)(Data + 5) : 0;
    u32 decode_buffer_size = (Size > 12) ? *(u32 *)(Data + 9) : 0;

    gf_isom_update_bitrate(iso_file, trackNumber, sampleDescriptionIndex, average_bitrate, max_bitrate, decode_buffer_size);

    u16 revision = (Size > 14) ? *(u16 *)(Data + 13) : 0;
    u32 vendor = (Size > 18) ? *(u32 *)(Data + 15) : 0;
    u32 temporalQ = (Size > 22) ? *(u32 *)(Data + 19) : 0;
    u32 spatialQ = (Size > 26) ? *(u32 *)(Data + 23) : 0;
    u32 horiz_res = (Size > 30) ? *(u32 *)(Data + 27) : 0;
    u32 vert_res = (Size > 34) ? *(u32 *)(Data + 31) : 0;
    u16 frames_per_sample = (Size > 36) ? *(u16 *)(Data + 35) : 0;
    const char *compressor_name = "dummy_compressor";
    s16 color_table_index = -1;

    gf_isom_update_video_sample_entry_fields(iso_file, trackNumber, sampleDescriptionIndex, revision, vendor, temporalQ, spatialQ, horiz_res, vert_res, frames_per_sample, compressor_name, color_table_index);

    char *URLname = NULL;
    char *URNname = NULL;
    u32 format_info = (Size > 40) ? *(u32 *)(Data + 37) : 0;
    u32 peak_data_rate = (Size > 44) ? *(u32 *)(Data + 41) : 0;
    u32 outDescriptionIndex = 0;

    gf_isom_truehd_config_new(iso_file, trackNumber, URLname, URNname, format_info, peak_data_rate, &outDescriptionIndex);

    cleanup_iso_file(iso_file);
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

        LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    