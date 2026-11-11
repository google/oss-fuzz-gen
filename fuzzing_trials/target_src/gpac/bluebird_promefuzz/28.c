#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile *create_dummy_isofile() {
    // Since GF_ISOFile is an opaque type, we cannot directly allocate it.
    // Instead, we assume there's a function to create or initialize it.
    GF_ISOFile *file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return file;
}

static void cleanup_isofile(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there is at least some data to work with

    // Create a dummy ISO file
    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    // Define variables for function parameters
    u32 trackNumber = Data[0] % 256; // Example of extracting data
    GF_ISOTrackID SourceTrackID = (Size > 1) ? Data[1] : 0;
    u32 sampleDescriptionIndex = (Size > 2) ? Data[2] : 0;
    u16 DataLength = (Size > 3) ? Data[3] : 0;
    u32 offsetInDescription = (Size > 4) ? Data[4] : 0;
    u8 AtBegin = (Size > 5) ? Data[5] : 0;

    // Invoke gf_isom_hint_sample_description_data
    gf_isom_hint_sample_description_data(isom_file, trackNumber, SourceTrackID, sampleDescriptionIndex, DataLength, offsetInDescription, AtBegin);

    // Set last sample duration
    u32 duration = (Size > 6) ? Data[6] : 0;
    gf_isom_set_last_sample_duration(isom_file, trackNumber, duration);

    // Hint sample data
    u32 SampleNumber = (Size > 7) ? Data[7] : 0;
    u32 offsetInSample = (Size > 8) ? Data[8] : 0;
    u8 *extra_data = NULL;
    if (Size > 10) {
        extra_data = (u8 *)malloc(Data[9]);
        if (extra_data) {
            memcpy(extra_data, &Data[10], Data[9]);
        }
    }
    gf_isom_hint_sample_data(isom_file, trackNumber, SourceTrackID, SampleNumber, DataLength, offsetInSample, extra_data, AtBegin);
    if (extra_data) free(extra_data);

    // Hint direct data
    u8 data[14];
    memcpy(data, Data, (Size < 14) ? Size : 14);
    gf_isom_hint_direct_data(isom_file, trackNumber, data, (Size < 14) ? Size : 14, AtBegin);

    // Set visual color info
    u32 colour_type = (Size > 11) ? Data[11] : 0;
    u16 colour_primaries = (Size > 12) ? Data[12] : 0;
    u16 transfer_characteristics = (Size > 13) ? Data[13] : 0;
    u16 matrix_coefficients = (Size > 14) ? Data[14] : 0;
    Bool full_range_flag = (Size > 15) ? Data[15] : 0;
    u8 *icc_data = NULL;
    u32 icc_size = (Size > 16) ? Data[16] : 0;
    if (icc_size > 0 && Size > 16 + icc_size) {
        icc_data = (u8 *)malloc(icc_size);
        if (icc_data) {
            memcpy(icc_data, &Data[17], icc_size);
        }
    }
    gf_isom_set_visual_color_info(isom_file, trackNumber, sampleDescriptionIndex, colour_type, colour_primaries, transfer_characteristics, matrix_coefficients, full_range_flag, icc_data, icc_size);
    if (icc_data) free(icc_data);

    // Set last sample duration ex
    u32 dur_num = (Size > 17 + icc_size) ? Data[17 + icc_size] : 0;
    u32 dur_den = (Size > 18 + icc_size) ? Data[18 + icc_size] : 0;
    gf_isom_set_last_sample_duration_ex(isom_file, trackNumber, dur_num, dur_den);

    // Cleanup
    cleanup_isofile(isom_file);
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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
