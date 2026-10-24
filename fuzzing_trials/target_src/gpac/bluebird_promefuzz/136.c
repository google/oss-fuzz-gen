#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    // Assuming GF_ISOFile has a function to properly delete it.
    // This is a placeholder for the actual cleanup function.
    // Replace `gf_isom_delete` with the actual cleanup function if available.
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_136(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return 0;

    // Create a dummy ISO file using the GPAC API
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!iso_file) return 0;

    u32 trackNumber = *(u32 *)Data;
    u32 sampleDescriptionIndex = *(u32 *)(Data + sizeof(u32));
    u32 dummySize = *(u32 *)(Data + 2 * sizeof(u32));

    // Fuzz gf_isom_get_rvc_config
    {
        u16 rvc_predefined;
        u8 *data = NULL;
        u32 size;
        const char *mime;
        gf_isom_get_rvc_config(iso_file, trackNumber, sampleDescriptionIndex, &rvc_predefined, &data, &size, &mime);
        free(data);
    }

    // Fuzz gf_isom_get_media_type
    {
        gf_isom_get_media_type(iso_file, trackNumber);
    }

    // Fuzz gf_isom_subtitle_get_mime
    {
        gf_isom_subtitle_get_mime(iso_file, trackNumber, sampleDescriptionIndex);
    }

    // Fuzz gf_isom_get_filename
    {
        gf_isom_get_filename(iso_file);
    }

    // Fuzz gf_isom_flac_config_new
    {
        u8 *metadata = (u8 *)malloc(dummySize);
        if (metadata) {
            u32 outDescriptionIndex;
            gf_isom_flac_config_new(iso_file, trackNumber, metadata, dummySize, NULL, NULL, &outDescriptionIndex);
            free(metadata);
        }
    }

    // Fuzz gf_isom_get_webvtt_config
    {
        gf_isom_get_webvtt_config(iso_file, trackNumber, sampleDescriptionIndex);
    }

    cleanup_iso_file(iso_file);
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

    LLVMFuzzerTestOneInput_136(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
