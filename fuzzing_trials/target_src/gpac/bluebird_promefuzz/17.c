#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void fuzz_gf_isom_get_stsd_template(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 2) return;

    u32 trackNumber = *((u32 *)Data);
    u32 sampleDescriptionIndex = *((u32 *)(Data + sizeof(u32)));
    u8 *output = NULL;
    u32 output_size = 0;

    gf_isom_get_stsd_template(isom_file, trackNumber, sampleDescriptionIndex, &output, &output_size);

    if (output) {
        free(output);
    }
}

static void fuzz_gf_isom_get_raw_user_data(GF_ISOFile *isom_file) {
    u8 *output = NULL;
    u32 output_size = 0;

    gf_isom_get_raw_user_data(isom_file, &output, &output_size);

    if (output) {
        free(output);
    }
}

static void fuzz_gf_isom_get_user_data(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 2 + sizeof(bin128)) return;

    u32 trackNumber = *((u32 *)Data);
    u32 UserDataType = *((u32 *)(Data + sizeof(u32)));
    bin128 UUID;
    memcpy(&UUID, Data + sizeof(u32) * 2, sizeof(bin128));
    u32 UserDataIndex = *((u32 *)(Data + sizeof(u32) * 2 + sizeof(bin128)));
    u8 *userData = NULL;
    u32 userDataSize = 0;

    gf_isom_get_user_data(isom_file, trackNumber, UserDataType, UUID, UserDataIndex, &userData, &userDataSize);

    if (userData) {
        free(userData);
    }
}

static void fuzz_gf_isom_get_track_template(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return;

    u32 trackNumber = *((u32 *)Data);
    u8 *output = NULL;
    u32 output_size = 0;

    gf_isom_get_track_template(isom_file, trackNumber, &output, &output_size);

    if (output) {
        free(output);
    }
}

static void fuzz_gf_isom_update_sample_description_from_template(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return;

    u32 trackNumber = *((u32 *)Data);
    u32 sampleDescriptionIndex = *((u32 *)(Data + sizeof(u32)));
    u32 dataSize = Size - sizeof(u32) * 2;
    u8 *data = (u8 *)(Data + sizeof(u32) * 2);

    gf_isom_update_sample_description_from_template(isom_file, trackNumber, sampleDescriptionIndex, data, dataSize);
}

static void fuzz_gf_isom_get_trex_template(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return;

    u32 trackNumber = *((u32 *)Data);
    u8 *output = NULL;
    u32 output_size = 0;

    gf_isom_get_trex_template(isom_file, trackNumber, &output, &output_size);

    if (output) {
        free(output);
    }
}

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    fuzz_gf_isom_get_stsd_template(isom_file, Data, Size);
    fuzz_gf_isom_get_raw_user_data(isom_file);
    fuzz_gf_isom_get_user_data(isom_file, Data, Size);
    fuzz_gf_isom_get_track_template(isom_file, Data, Size);
    fuzz_gf_isom_update_sample_description_from_template(isom_file, Data, Size);
    fuzz_gf_isom_get_trex_template(isom_file, Data, Size);

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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
