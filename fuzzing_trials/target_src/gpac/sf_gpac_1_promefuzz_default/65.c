// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_get_filename at isom_read.c:4068:13 in isomedia.h
// gf_isom_set_copyright at isom_write.c:3198:8 in isomedia.h
// gf_isom_switch_source at isom_read.c:6717:8 in isomedia.h
// gf_isom_start_segment at movie_fragments.c:2516:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void fuzz_gf_isom_get_filename(GF_ISOFile *isom_file) {
    const char *filename = gf_isom_get_filename(isom_file);
    if (filename) {
        printf("Filename: %s\n", filename);
    } else {
        printf("Filename is NULL.\n");
    }
}

static void fuzz_gf_isom_reset_sample_count(GF_ISOFile *isom_file) {
    gf_isom_reset_sample_count(isom_file);
}

static GF_ISOFile* fuzz_gf_isom_open(const uint8_t *Data, size_t Size) {
    char fileName[256];
    snprintf(fileName, sizeof(fileName), "./dummy_file_%zu", Size);
    FILE *file = fopen(fileName, "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);

    GF_ISOFile *isom_file = gf_isom_open(fileName, GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static void fuzz_gf_isom_start_segment(GF_ISOFile *isom_file) {
    GF_Err err = gf_isom_start_segment(isom_file, NULL, 0);
    if (err) {
        printf("Error starting segment: %d\n", err);
    }
}

static void fuzz_gf_isom_switch_source(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    char url[256];
    snprintf(url, sizeof(url), "gmem://%zu", Size);
    GF_Err err = gf_isom_switch_source(isom_file, url);
    if (err) {
        printf("Error switching source: %d\n", err);
    }
}

static void fuzz_gf_isom_set_copyright(GF_ISOFile *isom_file, const uint8_t *Data, size_t Size) {
    if (Size < 4) return;
    char language[4];
    memcpy(language, Data, 3);
    language[3] = '\0';
    char *notice = (char *)(Data + 3);
    GF_Err err = gf_isom_set_copyright(isom_file, language, notice);
    if (err) {
        printf("Error setting copyright: %d\n", err);
    }
}

int LLVMFuzzerTestOneInput_65(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = fuzz_gf_isom_open(Data, Size);
    if (!isom_file) return 0;

    fuzz_gf_isom_get_filename(isom_file);
    fuzz_gf_isom_reset_sample_count(isom_file);
    fuzz_gf_isom_start_segment(isom_file);
    fuzz_gf_isom_switch_source(isom_file, Data, Size);
    fuzz_gf_isom_set_copyright(isom_file, Data, Size);

    // Cleanup would typically be done here, but the specifics depend on the gpac library's API
    // For example: gf_isom_close(isom_file);

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

        LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    