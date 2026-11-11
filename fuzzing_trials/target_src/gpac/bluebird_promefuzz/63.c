#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
    // Ensure the input data is large enough to avoid buffer overflow
    if (Size < 36) return 0;

    // Initialize a dummy ISO file
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!isom_file) return 0;

    // Prepare parameters for API functions
    u32 trackNumber = 1;
    u32 sampleDescriptionIndex = 1;
    u32 average_bitrate = *((u32 *)Data) % 100000;
    u32 max_bitrate = *((u32 *)(Data + 4)) % 100000;
    u32 decode_buffer_size = *((u32 *)(Data + 8)) % 10000;
    Bool forced_for_mpeg4 = (Bool)(Data[12] % 2);
    Bool use_negative_offsets = (Bool)(Data[13] % 2);
    Bool CompactionOn = (Bool)(Data[14] % 2);
    Bool remove = (Bool)(Data[15] % 2);
    Bool all_ref_pics_intra = (Bool)(Data[16] % 2);
    Bool intra_pred_used = (Bool)(Data[17] % 2);
    u32 max_ref_per_pic = *((u32 *)(Data + 18)) % 10;
    u32 fps_num = *((u32 *)(Data + 22)) % 60 + 1;
    u32 fps_den = *((u32 *)(Data + 26)) % 60 + 1;
    s32 frames_per_counter_tick = *((s32 *)(Data + 30)) % 100;
    Bool is_drop = (Bool)(Data[34] % 2);
    Bool is_counter = (Bool)(Data[35] % 2);
    u32 outDescriptionIndex;

    // Call target API functions
    gf_isom_update_bitrate_ex(isom_file, trackNumber, sampleDescriptionIndex, average_bitrate, max_bitrate, decode_buffer_size, forced_for_mpeg4);
    gf_isom_set_composition_offset_mode(isom_file, trackNumber, use_negative_offsets);
    gf_isom_use_compact_size(isom_file, trackNumber, CompactionOn);
    gf_isom_set_image_sequence_coding_constraints(isom_file, trackNumber, sampleDescriptionIndex, remove, all_ref_pics_intra, intra_pred_used, max_ref_per_pic);
    gf_isom_tmcd_config_new(isom_file, trackNumber, fps_num, fps_den, frames_per_counter_tick, is_drop, is_counter, &outDescriptionIndex);
    gf_isom_set_image_sequence_alpha(isom_file, trackNumber, sampleDescriptionIndex, remove);
    
    // Cleanup
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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
