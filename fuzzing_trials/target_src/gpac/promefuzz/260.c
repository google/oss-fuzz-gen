// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_get_audio_info at isom_read.c:3880:8 in isomedia.h
// gf_isom_get_brand_info at isom_read.c:2631:8 in isomedia.h
// gf_isom_set_nalu_extract_mode at isom_read.c:5481:8 in isomedia.h
// gf_isom_get_nalu_extract_mode at isom_read.c:5499:23 in isomedia.h
// gf_isom_set_track_reference at isom_write.c:4967:8 in isomedia.h
// gf_isom_get_tmcd_config at sample_descs.c:1953:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_260(const uint8_t *Data, size_t Size) {
    // Ensure there's enough data for basic operations
    if (Size < 4) {
        return 0;
    }

    // Create a dummy ISO file
    write_dummy_file(Data, Size);
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);

    if (!isom_file) {
        return 0;
    }

    u32 trackNumber = Data[0];
    u32 sampleDescriptionIndex = Data[1];
    u32 SampleRate = 0, Channels = 0, bitsPerSample = 0;
    gf_isom_get_audio_info(isom_file, trackNumber, sampleDescriptionIndex, &SampleRate, &Channels, &bitsPerSample);

    u32 brand = 0, minorVersion = 0, AlternateBrandsCount = 0;
    gf_isom_get_brand_info(isom_file, &brand, &minorVersion, &AlternateBrandsCount);

    GF_ISONaluExtractMode nalu_extract_mode = Data[2];
    gf_isom_set_nalu_extract_mode(isom_file, trackNumber, nalu_extract_mode);

    gf_isom_get_nalu_extract_mode(isom_file, trackNumber);

    u32 referenceType = Data[3];
    GF_ISOTrackID ReferencedTrackID = trackNumber; // Use trackNumber as a dummy ID for reference
    gf_isom_set_track_reference(isom_file, trackNumber, referenceType, ReferencedTrackID);

    u32 tmcd_flags = 0, tmcd_fps_num = 0, tmcd_fps_den = 0, tmcd_fpt = 0;
    gf_isom_get_tmcd_config(isom_file, trackNumber, sampleDescriptionIndex, &tmcd_flags, &tmcd_fps_num, &tmcd_fps_den, &tmcd_fpt);

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

        LLVMFuzzerTestOneInput_260(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    