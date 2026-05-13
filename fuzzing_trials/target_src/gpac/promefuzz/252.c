// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open_progressive_ex at isom_read.c:435:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_open_segment at isom_read.c:3557:8 in isomedia.h
// gf_isom_close_segment at movie_fragments.c:1743:8 in isomedia.h
// gf_isom_get_root_sidx_offsets at isom_read.c:6083:6 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_252(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file(Data, Size);

    GF_ISOFile *isom_file = NULL;
    u64 BytesMissing = 0;
    u32 topBoxType = 0;
    u64 start_range = 0;
    u64 end_range = Size;
    Bool enable_frag_templates = 1;

    GF_Err result = gf_isom_open_progressive_ex("./dummy_file", start_range, end_range, enable_frag_templates, &isom_file, &BytesMissing, &topBoxType);
    if (result == GF_OK && isom_file) {
        u64 top_box_start = 0;
        gf_isom_reset_data_offset(isom_file, &top_box_start);

        u64 segment_start = 0;
        u64 segment_end = 0;
        GF_ISOSegOpenMode flags = 0;
        gf_isom_open_segment(isom_file, "./dummy_file", start_range, end_range, flags);

        u64 index_start_range = 0;
        u64 index_end_range = 0;
        u64 out_seg_size = 0;
        gf_isom_close_segment(isom_file, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, &index_start_range, &index_end_range, &out_seg_size);

        u64 start = 0;
        u64 end = 0;
        gf_isom_get_root_sidx_offsets(isom_file, &start, &end);

        gf_isom_reset_data_offset(isom_file, NULL);
    }

    if (isom_file) {
        // Assuming there exists a function to properly close and free the isom_file
        // gf_isom_close(isom_file);
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

        LLVMFuzzerTestOneInput_252(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    