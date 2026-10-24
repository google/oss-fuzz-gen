// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_release_segment at isom_read.c:3459:8 in isomedia.h
// gf_isom_remove_meta_xml at meta.c:678:8 in isomedia.h
// gf_isom_set_qt_key at isom_write.c:6772:8 in isomedia.h
// gf_isom_text_set_streaming_mode at isom_read.c:3688:8 in isomedia.h
// gf_isom_make_interleave_ex at isom_write.c:6151:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
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

int LLVMFuzzerTestOneInput_65(const uint8_t *Data, size_t Size) {
    if (Size < 12) {
        return 0;
    }

    GF_ISOFile *isom_file = NULL;
    GF_QT_UDTAKey *key = NULL;
    GF_Fraction fraction;

    // Initialize dummy data
    write_dummy_file(Data, Size);

    // Create a dummy ISO file structure
    isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_EDIT, NULL);
    if (!isom_file) return 0;

    // Fuzz gf_isom_release_segment
    gf_isom_release_segment(isom_file, Data[0] % 2);

    // Fuzz gf_isom_remove_meta_xml
    gf_isom_remove_meta_xml(isom_file, Data[1] % 2, (u32)Data[2]);

    // Fuzz gf_isom_set_qt_key
    gf_isom_set_qt_key(isom_file, key);

    // Fuzz gf_isom_text_set_streaming_mode
    gf_isom_text_set_streaming_mode(isom_file, Data[3] % 2);

    // Fuzz gf_isom_make_interleave_ex
    fraction.num = (u32)Data[4];
    fraction.den = (u32)Data[5];
    gf_isom_make_interleave_ex(isom_file, &fraction);

    // Close the ISO file
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

        LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    