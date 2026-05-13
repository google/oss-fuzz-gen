#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *f = fopen("./dummy_file", "wb");
    if (f) {
        fwrite(Data, 1, Size, f);
        fclose(f);
    }
}

int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return 0;

    // Write the input data to a dummy file
    write_dummy_file(Data, Size);

    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ_EDIT, NULL);
    if (!isom_file) return 0;

    u32 trackNumber = *((u32 *)Data);
    u32 sampleDescriptionIndex = *((u32 *)(Data + sizeof(u32)));
    u32 additionalParam = *((u32 *)(Data + 2 * sizeof(u32)));

    // Fuzz gf_isom_remove_track
    gf_isom_remove_track(isom_file, trackNumber);

    // Fuzz gf_isom_get_esd
    GF_ESD *esd = gf_isom_get_esd(isom_file, trackNumber, sampleDescriptionIndex);
    if (esd) {
        gf_odf_desc_del((GF_Descriptor *)esd);
    }

    // Fuzz gf_isom_get_pcm_config
    u32 flags = 0;
    u32 pcm_size = 0;
    gf_isom_get_pcm_config(isom_file, trackNumber, sampleDescriptionIndex, &flags, &pcm_size);

    // Fuzz gf_isom_change_mpeg4_description
    GF_ESD newESD;
    gf_isom_change_mpeg4_description(isom_file, trackNumber, sampleDescriptionIndex, &newESD);

    // Fuzz gf_isom_new_mpeg4_description
    u32 outDescriptionIndex = 0;
    gf_isom_new_mpeg4_description(isom_file, trackNumber, &newESD, NULL, NULL, &outDescriptionIndex);

    // Fuzz gf_isom_get_visual_info
    u32 Width = 0;
    u32 Height = 0;
    gf_isom_get_visual_info(isom_file, trackNumber, sampleDescriptionIndex, &Width, &Height);

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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
