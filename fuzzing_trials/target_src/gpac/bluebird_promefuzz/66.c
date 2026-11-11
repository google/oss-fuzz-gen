#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* initialize_iso_file() {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return isom_file;
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_66(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 8 + sizeof(s16)) return 0;

    GF_ISOFile *isom_file = initialize_iso_file();
    if (!isom_file) return 0;

    u32 trackNumber = *((u32 *)Data);
    u32 sampleNumber = *((u32 *)(Data + sizeof(u32)));
    GF_ISOSampleRollType roll_type = *((GF_ISOSampleRollType *)(Data + sizeof(u32) * 2));
    s16 roll_distance = *((s16 *)(Data + sizeof(u32) * 3));
    u32 nb_samples = *((u32 *)(Data + sizeof(u32) * 3 + sizeof(s16)));
    u32 HintDescriptionIndex = *((u32 *)(Data + sizeof(u32) * 4 + sizeof(s16)));
    u32 SequenceNumberOffset = *((u32 *)(Data + sizeof(u32) * 5 + sizeof(s16)));
    u32 sampleDescriptionIndex = *((u32 *)(Data + sizeof(u32) * 6 + sizeof(s16)));
    u32 new_type = *((u32 *)(Data + sizeof(u32) * 7 + sizeof(s16)));

    GF_Err result;

    result = gf_isom_set_sample_roll_group(isom_file, trackNumber, sampleNumber, roll_type, roll_distance);

    result = gf_isom_purge_samples(isom_file, trackNumber, nb_samples);

    result = gf_isom_rtp_set_time_sequence_offset(isom_file, trackNumber, HintDescriptionIndex, SequenceNumberOffset);

    result = gf_isom_fragment_set_sample_roll_group(isom_file, trackNumber, sampleNumber, roll_type, roll_distance);

    result = gf_isom_set_media_subtype(isom_file, trackNumber, sampleDescriptionIndex, new_type);

    result = gf_isom_cenc_allocate_storage(isom_file, trackNumber);

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

    LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
