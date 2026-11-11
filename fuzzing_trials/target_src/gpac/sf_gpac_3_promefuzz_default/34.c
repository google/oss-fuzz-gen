// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_release_segment at isom_read.c:3459:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_extract_meta_item at meta.c:494:8 in isomedia.h
// gf_isom_set_meta_type at meta.c:612:8 in isomedia.h
// gf_isom_remove_meta_xml at meta.c:678:8 in isomedia.h
// gf_isom_text_set_streaming_mode at isom_read.c:3688:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy ISO file
    GF_ISOFile *isom_file = create_dummy_iso_file();
    if (!isom_file) return 0;

    // Fuzz gf_isom_release_segment
    Bool reset_tables = Data[0] % 2;
    gf_isom_release_segment(isom_file, reset_tables);

    // Fuzz gf_isom_close
    gf_isom_close(isom_file);

    // Re-open the file for further operations
    isom_file = create_dummy_iso_file();
    if (!isom_file) return 0;

    // Fuzz gf_isom_extract_meta_item
    Bool root_meta = (Data[0] >> 1) % 2;
    u32 track_num = (Size > 1) ? Data[1] : 0;
    u32 item_num = (Size > 2) ? Data[2] : 1;
    gf_isom_extract_meta_item(isom_file, root_meta, track_num, item_num, NULL);

    // Fuzz gf_isom_set_meta_type
    u32 metaType = (Size > 3) ? Data[3] : 0;
    gf_isom_set_meta_type(isom_file, root_meta, track_num, metaType);

    // Fuzz gf_isom_remove_meta_xml
    gf_isom_remove_meta_xml(isom_file, root_meta, track_num);

    // Fuzz gf_isom_text_set_streaming_mode
    Bool do_convert = (Data[0] >> 2) % 2;
    gf_isom_text_set_streaming_mode(isom_file, do_convert);

    // Clean up
    cleanup_iso_file(isom_file);

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

        LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    