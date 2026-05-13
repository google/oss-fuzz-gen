#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* initialize_iso_file(const uint8_t *Data, size_t Size) {
    // The GF_ISOFile type is opaque, so we cannot directly allocate or manipulate it.
    // Assume there's a function to create or open an ISO file for fuzzing purposes.
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!isom_file) return NULL;

    // Assume we have a way to write initial data to the file if needed
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (dummy_file) {
        fwrite(Data, 1, Size, dummy_file);
        fclose(dummy_file);
    }

    return isom_file;
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
        remove("./dummy_file");
    }
}

int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size) {
    if (Size < 5) return 0; // Ensure we have enough data to read

    GF_ISOFile *isom_file = initialize_iso_file(Data, Size);
    if (!isom_file) return 0;

    u32 trackNumber = Data[0];
    u32 maxChunkDur = Data[1];
    u32 new_timescale = Data[2];
    u32 new_tsinc = Data[3];
    u32 force_rescale_type = Data[4 % Size];
    u32 dur_min, dur_avg, dur_max, size_min, size_avg, size_max;

    // Invoke target functions
    gf_isom_hint_max_chunk_duration(isom_file, trackNumber, maxChunkDur);
    gf_isom_set_media_timescale(isom_file, trackNumber, new_timescale, new_tsinc, force_rescale_type);
    gf_isom_add_track_to_root_od(isom_file, trackNumber);
    gf_isom_rewrite_track_dependencies(isom_file, trackNumber);
    gf_isom_get_chunks_infos(isom_file, trackNumber, &dur_min, &dur_avg, &dur_max, &size_min, &size_avg, &size_max);
    gf_isom_purge_track_reference(isom_file, trackNumber);

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

    LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
