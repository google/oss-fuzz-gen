// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_release_segment at isom_read.c:3459:8 in isomedia.h
// gf_isom_start_segment at movie_fragments.c:2516:8 in isomedia.h
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_get_filename at isom_read.c:4068:13 in isomedia.h
// gf_isom_switch_source at isom_read.c:6717:8 in isomedia.h
// gf_isom_set_copyright at isom_write.c:3198:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "isomedia.h"

#define DUMMY_FILE "./dummy_file"

int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile *isom_file = gf_isom_open(DUMMY_FILE, GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    // Create a dummy file if needed
    FILE *file = fopen(DUMMY_FILE, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    // Fuzz gf_isom_release_segment
    Bool reset_tables = Data[0] % 2;
    gf_isom_release_segment(isom_file, reset_tables);

    // Fuzz gf_isom_start_segment
    const char *seg_name = (Size > 1) ? (const char *)(Data + 1) : NULL;
    Bool memory_mode = (Size > 2) ? Data[2] % 2 : 0;
    gf_isom_start_segment(isom_file, seg_name, memory_mode);

    // Fuzz gf_isom_reset_sample_count
    gf_isom_reset_sample_count(isom_file);

    // Fuzz gf_isom_get_filename
    const char *filename = gf_isom_get_filename(isom_file);
    if (filename) {
        // Use filename for something if needed
    }

    // Fuzz gf_isom_switch_source
    const char *new_url = (Size > 3) ? (const char *)(Data + 3) : NULL;
    gf_isom_switch_source(isom_file, new_url);

    // Fuzz gf_isom_set_copyright
    const char *three_char_code = (Size > 4) ? (const char *)(Data + 4) : "eng";
    char *notice = (Size > 5) ? (char *)(Data + 5) : "Default Notice";
    gf_isom_set_copyright(isom_file, three_char_code, notice);

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

        LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    