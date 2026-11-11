#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // As the structure of GF_ISOFile is not defined, we cannot allocate it directly.
    // Assuming a function or mechanism exists in the library to create or open an ISO file.
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return iso_file;
}

int LLVMFuzzerTestOneInput_95(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return 0;

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = *((u32 *)Data);
    u32 sampleNumber = *((u32 *)(Data + sizeof(u32)));
    s32 timeOffset = *((s32 *)(Data + sizeof(u32) * 2));

    u32 width, height;
    s32 translation_x, translation_y;
    s16 layer;

    // Fuzz gf_isom_get_track_layout_info
    GF_Err err = gf_isom_get_track_layout_info(iso_file, trackNumber, &width, &height, &translation_x, &translation_y, &layer);

    // Fuzz gf_isom_get_min_negative_cts_offset
    s32 min_cts_offset = gf_isom_get_min_negative_cts_offset(iso_file, trackNumber, 0);

    // Fuzz gf_isom_get_sample_duration
    u32 sample_duration = gf_isom_get_sample_duration(iso_file, trackNumber, sampleNumber);

    // Fuzz gf_isom_get_sample_size
    u32 sample_size = gf_isom_get_sample_size(iso_file, trackNumber, sampleNumber);

    // Fuzz gf_isom_rtp_packet_set_offset
    err = gf_isom_rtp_packet_set_offset(iso_file, trackNumber, timeOffset);

    // Fuzz gf_isom_get_composition_offset_shift
    s32 composition_offset_shift = gf_isom_get_composition_offset_shift(iso_file, trackNumber);

    gf_isom_close(iso_file);
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

    LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
