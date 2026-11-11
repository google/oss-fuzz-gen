#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* initialize_iso_file(const uint8_t *Data, size_t Size) {
    // Initialize a dummy ISO file
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!iso_file) return NULL;

    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        gf_isom_close(iso_file);
        return NULL;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);
    return iso_file;
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
        remove("./dummy_file");
    }
}

int LLVMFuzzerTestOneInput_67(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 2 + sizeof(u64)) return 0; // Ensure enough data for track, time, and sample numbers

    GF_ISOFile *iso_file = initialize_iso_file(Data, Size);
    if (!iso_file) return 0;

    u32 trackNumber = *(u32 *)Data;
    u64 for_time = *(u64 *)(Data + sizeof(u32));
    u32 sampleNumber = *(u32 *)(Data + sizeof(u32) + sizeof(u64));

    u64 decode_time = 0;

    // Fuzz gf_isom_get_media_original_duration
    u64 duration = gf_isom_get_media_original_duration(iso_file, trackNumber);

    // Fuzz gf_isom_get_sample_description_index
    u32 sample_desc_index = gf_isom_get_sample_description_index(iso_file, trackNumber, for_time);

    // Fuzz gf_isom_get_current_tfdt
    u64 current_tfdt = gf_isom_get_current_tfdt(iso_file, trackNumber);

    // Fuzz gf_isom_get_sample_dts
    u64 sample_dts = gf_isom_get_sample_dts(iso_file, trackNumber, sampleNumber);

    // Fuzz gf_isom_segment_get_track_fragment_decode_time
    u32 track_id = gf_isom_segment_get_track_fragment_decode_time(iso_file, trackNumber, sampleNumber, &decode_time);

    // Fuzz gf_isom_get_media_data_size
    u64 media_data_size = gf_isom_get_media_data_size(iso_file, trackNumber);

    // Cleanup
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

    LLVMFuzzerTestOneInput_67(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
