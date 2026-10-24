// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open_progressive_ex at isom_read.c:435:8 in isomedia.h
// gf_isom_segment_get_fragment_size at isom_read.c:927:5 in isomedia.h
// gf_isom_get_pssh_count at isom_read.c:5559:5 in isomedia.h
// gf_isom_set_inplace_padding at isom_read.c:88:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_get_num_supported_boxes at box_funcs.c:1880:5 in isomedia.h
// gf_isom_get_supported_box_type at box_funcs.c:2355:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

#define DUMMY_FILE "./dummy_file"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_130(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare environment
    write_dummy_file(Data, Size);

    // Fuzz gf_isom_open_progressive_ex
    GF_ISOFile *isom_file = NULL;
    u64 BytesMissing = 0;
    u32 topBoxType = 0;
    u64 start_range = 0;
    u64 end_range = Size > 8 ? *(u64 *)(Data + 1) : 0;
    Bool enable_frag_templates = Data[0] % 2;

    gf_isom_open_progressive_ex(DUMMY_FILE, start_range, end_range, enable_frag_templates, &isom_file, &BytesMissing, &topBoxType);

    if (isom_file) {
        // Fuzz gf_isom_segment_get_fragment_size
        u32 moof_size = 0;
        gf_isom_segment_get_fragment_size(isom_file, 1, &moof_size);

        // Fuzz gf_isom_get_pssh_count
        gf_isom_get_pssh_count(isom_file);

        // Fuzz gf_isom_set_inplace_padding
        gf_isom_set_inplace_padding(isom_file, 128);

        // Clean up
        gf_isom_close(isom_file);
    }

    // Fuzz gf_isom_get_num_supported_boxes
    u32 num_boxes = gf_isom_get_num_supported_boxes();

    // Fuzz gf_isom_get_supported_box_type
    if (num_boxes > 0) {
        for (u32 i = 0; i < num_boxes; i++) {
            gf_isom_get_supported_box_type(i);
        }
    }

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

        LLVMFuzzerTestOneInput_130(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    