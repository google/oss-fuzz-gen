#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

#define DUMMY_FILE_PATH "./dummy_file"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE_PATH, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_155(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3 + sizeof(Bool)) return 0;

    write_dummy_file(Data, Size);

    GF_ISOFile *isom_file = gf_isom_open(DUMMY_FILE_PATH, GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    u32 trackNumber = *((u32 *)Data);
    u32 sampleDescriptionIndex = *((u32 *)(Data + sizeof(u32)));
    u32 sampleNumber = *((u32 *)(Data + sizeof(u32) * 2));
    Bool keep_xps = *((Bool *)(Data + sizeof(u32) * 3));
    Bool is_rap = *((Bool *)(Data + sizeof(u32) * 3 + sizeof(Bool)));

    gf_isom_hevc_set_inband_config(isom_file, trackNumber, sampleDescriptionIndex, keep_xps);
    gf_isom_avc_set_inband_config(isom_file, trackNumber, sampleDescriptionIndex, keep_xps);
    gf_isom_set_sample_av1_switch_frame_group(isom_file, trackNumber, sampleNumber, is_rap);
    gf_isom_vvc_set_inband_config(isom_file, trackNumber, sampleDescriptionIndex, keep_xps);
    gf_isom_set_image_sequence_coding_constraints(isom_file, trackNumber, sampleDescriptionIndex, keep_xps, is_rap, keep_xps, sampleNumber);
    gf_isom_fragment_set_sample_av1_switch_frame_group(isom_file, trackNumber, sampleNumber, is_rap);

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

    LLVMFuzzerTestOneInput_155(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
