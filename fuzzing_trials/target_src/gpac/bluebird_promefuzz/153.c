#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void dummy_track_num_changed_callback(void *udta, u32 old_track_num, u32 new_track_num) {
    // Dummy callback function
}

int LLVMFuzzerTestOneInput_153(const uint8_t *Data, size_t Size) {
    // Create a dummy ISO file structure
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!iso_file) return 0;

    // Write the input data to a dummy file
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (!dummy_file) {
        gf_isom_close(iso_file);
        return 0;
    }
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    // Extract some values from the input data
    u32 trackNumber = (Size > 4) ? Data[0] : 1;
    u32 nb_samples = (Size > 8) ? Data[1] : 1;
    u32 sampleDescriptionIndex = (Size > 12) ? Data[2] : 1;
    u32 average_bitrate = (Size > 16) ? Data[3] : 0;
    u32 max_bitrate = (Size > 20) ? Data[4] : 0;
    u32 decode_buffer_size = (Size > 24) ? Data[5] : 0;
    u32 sampleNumber = (Size > 28) ? Data[6] : 1;
    u32 dur_num = (Size > 32) ? Data[7] : 1;
    u32 dur_den = (Size > 36) ? Data[8] : 1;
    u32 index = (Size > 40) ? Data[9] : 1;

    // Dummy variables for function calls
    u32 refID, nb_refs;
    const u32 *refs;

    // Call the target functions with the extracted values
    gf_isom_purge_samples(iso_file, trackNumber, nb_samples);
    gf_isom_check_data_reference(iso_file, trackNumber, sampleDescriptionIndex);
    gf_isom_update_bitrate(iso_file, trackNumber, sampleDescriptionIndex, average_bitrate, max_bitrate, decode_buffer_size);
    gf_isom_get_sample_references(iso_file, trackNumber, sampleNumber, &refID, &nb_refs, &refs);
    gf_isom_set_track_index(iso_file, trackNumber, index, dummy_track_num_changed_callback, NULL);
    gf_isom_set_last_sample_duration_ex(iso_file, trackNumber, dur_num, dur_den);

    // Clean up
    gf_isom_close(iso_file);
    remove("./dummy_file");

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

    LLVMFuzzerTestOneInput_153(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
