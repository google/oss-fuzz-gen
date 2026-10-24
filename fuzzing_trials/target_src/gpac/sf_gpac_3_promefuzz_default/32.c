// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_sdp_add_track_line at hint_track.c:740:8 in isomedia.h
// gf_isom_sdp_get at hint_track.c:909:8 in isomedia.h
// gf_isom_rtp_set_timescale at hint_track.c:226:8 in isomedia.h
// gf_isom_set_final_name at isom_write.c:1668:8 in isomedia.h
// gf_isom_sdp_add_line at hint_track.c:820:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // Creating a dummy file for the purpose of fuzzing
    FILE *dummy_file = fopen("./dummy_file", "w");
    if (dummy_file) {
        fputs("dummy content", dummy_file);
        fclose(dummy_file);
    }

    // Use gpac provided function to open ISO file
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static void cleanup_isofile(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    // Fuzz gf_isom_sdp_add_track_line
    if (Size > 0) {
        u32 trackNumber = Data[0];
        const char *text = (const char *)(Data + 1);
        gf_isom_sdp_add_track_line(isom_file, trackNumber, text);
    }

    // Fuzz gf_isom_sdp_get
    const char *sdp;
    u32 length;
    gf_isom_sdp_get(isom_file, &sdp, &length);

    // Fuzz gf_isom_rtp_set_timescale
    if (Size > 3) {
        u32 trackNumber = Data[1];
        u32 HintDescriptionIndex = Data[2];
        u32 TimeScale = Data[3];
        gf_isom_rtp_set_timescale(isom_file, trackNumber, HintDescriptionIndex, TimeScale);
    }

    // Fuzz gf_isom_set_final_name
    if (Size > 4) {
        char *filename = (char *)(Data + 4);
        gf_isom_set_final_name(isom_file, filename);
    }

    // Fuzz gf_isom_sdp_add_line
    if (Size > 5) {
        const char *text = (const char *)(Data + 5);
        gf_isom_sdp_add_line(isom_file, text);
    }

    cleanup_isofile(isom_file);
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

        LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    