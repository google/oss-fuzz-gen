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

static GF_ISOFile *create_dummy_iso_file() {
    // We cannot allocate GF_ISOFile directly since its size is unknown
    // Instead, we use a helper function from the library to create a dummy file
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
}

static void cleanup_iso_file(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 13) return 0; // Ensure there's enough data

    GF_ISOFile *isoFile = create_dummy_iso_file();
    if (!isoFile) return 0;

    u32 compress_mode = *(u32 *)Data;
    u32 compress_flags = *(u32 *)(Data + 4);
    u32 trackNumber = *(u32 *)(Data + 8);
    u32 HintDescriptionIndex = *(u32 *)(Data + 12);
    u32 TimeOffset = *(u32 *)(Data + 16);
    u32 timeScale = *(u32 *)(Data + 20);
    u32 referenceType = *(u32 *)(Data + 24);
    GF_ISOTrackID ReferencedTrackID = *(GF_ISOTrackID *)(Data + 28);
    u32 sampleNumber = *(u32 *)(Data + 32);
    u32 isLeading = *(u32 *)(Data + 36);
    u32 dependsOn = *(u32 *)(Data + 40);
    u32 dependedOn = *(u32 *)(Data + 44);
    u32 redundant = *(u32 *)(Data + 48);

    gf_isom_enable_compression(isoFile, compress_mode, compress_flags);
    gf_isom_rtp_set_time_offset(isoFile, trackNumber, HintDescriptionIndex, TimeOffset);
    gf_isom_set_timescale(isoFile, timeScale);
    gf_isom_set_track_reference(isoFile, trackNumber, referenceType, ReferencedTrackID);
    gf_isom_set_sample_flags(isoFile, trackNumber, sampleNumber, isLeading, dependsOn, dependedOn, redundant);

    GF_UDTSConfig udtsConfig;
    gf_isom_get_udts_config(isoFile, trackNumber, HintDescriptionIndex, &udtsConfig);

    cleanup_iso_file(isoFile);
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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
