#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void write_dummy_file(const char *filename, const uint8_t *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(data, 1, size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    // Step 1: Prepare the environment for API functions
    const char *tmp_dir = "/tmp";
    GF_ISOFile *orig_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, tmp_dir);
    GF_ISOFile *dest_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, tmp_dir);
    u32 orig_track = 1;
    GF_ISOTrackCloneFlags flags = 0;
    u32 dest_track;
    u32 trackNumber = 1;
    u32 sampleDescriptionIndex = 1;
    u32 new_type = 0x6D703431; // 'mp41'
    u32 nalu_size_length = 4;
    const u32 *profiles = NULL;
    u32 nb_compatible_profiles = 0;

    // Write a dummy file for testing
    write_dummy_file("./dummy_file", Data, Size);

    if (orig_file && dest_file) {
        // Step 2: Invoke each target function with prepared data
        gf_isom_clone_track(orig_file, orig_track, dest_file, flags, &dest_track);
        gf_isom_remove_cenc_seig_sample_group(orig_file, trackNumber);
        gf_isom_set_mpegh_compatible_profiles(orig_file, trackNumber, sampleDescriptionIndex, profiles, nb_compatible_profiles);
        gf_isom_set_media_subtype(orig_file, trackNumber, sampleDescriptionIndex, new_type);
        gf_isom_set_nalu_length_field(orig_file, trackNumber, sampleDescriptionIndex, nalu_size_length);
        gf_isom_mvc_config_del(orig_file, trackNumber, sampleDescriptionIndex);

        // Step 3: Cleanup
        gf_isom_close(orig_file);
        gf_isom_close(dest_file);
    }

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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
