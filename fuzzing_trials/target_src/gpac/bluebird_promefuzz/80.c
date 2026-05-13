#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Since GF_ISOFile is an incomplete type, we cannot allocate it directly
    // Assuming we have a function to create or open an ISO file in the actual library
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_80(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return 0;

    GF_ISOFile *isom_file = create_dummy_iso_file();
    if (!isom_file) return 0;

    u32 trackNumber = *((u32 *)Data);

    // Fuzz gf_isom_get_track_id
    GF_ISOTrackID track_id = gf_isom_get_track_id(isom_file, trackNumber);

    // Fuzz gf_isom_get_max_sample_cts_offset
    u32 max_cts_offset = gf_isom_get_max_sample_cts_offset(isom_file, trackNumber);

    // Fuzz gf_isom_get_track_original_id
    GF_ISOTrackID original_track_id = gf_isom_get_track_original_id(isom_file, trackNumber);

    // Fuzz gf_isom_get_edit_list_type
    s64 mediaOffset = 0;
    Bool edit_list_type = gf_isom_get_edit_list_type(isom_file, trackNumber, &mediaOffset);

    // Fuzz gf_isom_get_cts_to_dts_shift
    s64 cts_to_dts_shift = gf_isom_get_cts_to_dts_shift(isom_file, trackNumber);

    // Fuzz gf_isom_get_constant_sample_duration
    u32 constant_sample_duration = gf_isom_get_constant_sample_duration(isom_file, trackNumber);

    // Cleanup
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

    LLVMFuzzerTestOneInput_80(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
