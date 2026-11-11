#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Create a dummy ISO file object for testing
    GF_ISOFile* file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return file;
}

static void destroy_dummy_iso_file(GF_ISOFile* file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_84(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0; // Ensure there is enough data to read

    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (!dummy_file) return 0;
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    GF_ISOFile *isom_file = create_dummy_iso_file();
    if (!isom_file) return 0;

    // Fuzz gf_isom_setup_track_fragment
    gf_isom_setup_track_fragment(isom_file, Data[0], Data[1], Data[2], Data[3], Data[4], Data[5], Data[6], 1);

    // Fuzz gf_isom_get_sample_padding_bits
    u8 padding_bits;
    gf_isom_get_sample_padding_bits(isom_file, Data[0], Data[1], &padding_bits);

    // Fuzz gf_isom_fragment_add_sample
    GF_ISOSample sample;
    memset(&sample, 0, sizeof(GF_ISOSample));
    gf_isom_fragment_add_sample(isom_file, Data[0], &sample, Data[1], Data[2], Data[3], Data[4], 1);

    // Fuzz gf_isom_get_fragment_defaults
    u32 defaultDuration, defaultSize, defaultDescriptionIndex, defaultRandomAccess;
    u8 defaultPadding;
    u16 defaultDegradationPriority;
    gf_isom_get_fragment_defaults(isom_file, Data[0], &defaultDuration, &defaultSize, &defaultDescriptionIndex,
                                  &defaultRandomAccess, &defaultPadding, &defaultDegradationPriority);

    // Fuzz gf_isom_change_track_fragment_defaults
    gf_isom_change_track_fragment_defaults(isom_file, Data[0], Data[1], Data[2], Data[3], Data[4], Data[5], Data[6], 1);

    // Fuzz gf_isom_end_hint_sample
    gf_isom_end_hint_sample(isom_file, Data[0], Data[1]);

    destroy_dummy_iso_file(isom_file);
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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
