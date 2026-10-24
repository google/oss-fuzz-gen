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

int LLVMFuzzerTestOneInput_144(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 4 + sizeof(GF_ISOM_Y3D_Info) + 1) {
        return 0;
    }

    GF_ISOFile *isom_file = NULL; // Assuming a function exists to create or open an ISO file
    u32 trackNumber = *((u32 *)(Data));
    u32 sampleDescriptionIndex = *((u32 *)(Data + sizeof(u32)));
    u32 outDescriptionIndex;
    GF_ISOM_Y3D_Info y3d_info;
    u32 tmcd_flags, tmcd_fps_num, tmcd_fps_den, tmcd_fpt;
    u32 sampleRate = *((u32 *)(Data + sizeof(u32) * 2));
    u32 nbChannels = *((u32 *)(Data + sizeof(u32) * 3));
    u8 bitsPerSample = *(Data + sizeof(u32) * 4);
    GF_AudioSampleEntryImportMode asemode = (GF_AudioSampleEntryImportMode)*(Data + sizeof(u32) * 4 + 1);

    write_dummy_file(Data, Size);

    // Fuzz gf_isom_evte_config_new
    gf_isom_evte_config_new(isom_file, trackNumber, &outDescriptionIndex);

    // Fuzz gf_isom_get_y3d_info
    gf_isom_get_y3d_info(isom_file, trackNumber, sampleDescriptionIndex, &y3d_info);

    // Fuzz gf_isom_set_forced_text
    gf_isom_set_forced_text(isom_file, trackNumber, sampleDescriptionIndex, bitsPerSample % 3);

    // Fuzz gf_isom_set_y3d_info
    gf_isom_set_y3d_info(isom_file, trackNumber, sampleDescriptionIndex, &y3d_info);

    // Fuzz gf_isom_get_tmcd_config
    gf_isom_get_tmcd_config(isom_file, trackNumber, sampleDescriptionIndex, &tmcd_flags, &tmcd_fps_num, &tmcd_fps_den, &tmcd_fpt);

    // Fuzz gf_isom_set_audio_info
    gf_isom_set_audio_info(isom_file, trackNumber, sampleDescriptionIndex, sampleRate, nbChannels, bitsPerSample, asemode);

    // Assuming a function exists to cleanup or close the ISO file
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

    LLVMFuzzerTestOneInput_144(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
