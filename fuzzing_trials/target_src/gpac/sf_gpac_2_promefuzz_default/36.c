// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_enable_compression at isom_write.c:2779:8 in isomedia.h
// gf_isom_reset_switch_parameters at isom_write.c:7134:8 in isomedia.h
// gf_isom_set_interleave_time at isom_write.c:3550:8 in isomedia.h
// gf_isom_open_segment at isom_read.c:3557:8 in isomedia.h
// gf_isom_rewrite_track_dependencies at isom_write.c:5239:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
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

int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) + sizeof(u32) * 3 + sizeof(GF_ISOSegOpenMode)) {
        return 0;
    }

    // Prepare dummy file
    write_dummy_file(Data, Size);

    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!iso_file) {
        return 0;
    }

    // Prepare parameters for the functions
    u64 top_box_start = *((u64 *)Data);
    Data += sizeof(u64);
    Size -= sizeof(u64);

    GF_ISOCompressMode compress_mode = (GF_ISOCompressMode)(*Data);
    Data += sizeof(u32);
    Size -= sizeof(u32);

    u32 compress_flags = *((u32 *)Data);
    Data += sizeof(u32);
    Size -= sizeof(u32);

    u32 interleave_time = *((u32 *)Data);
    Data += sizeof(u32);
    Size -= sizeof(u32);

    u64 start_range = 0;
    u64 end_range = Size;
    GF_ISOSegOpenMode flags = (GF_ISOSegOpenMode)(*Data);
    Data += sizeof(GF_ISOSegOpenMode);
    Size -= sizeof(GF_ISOSegOpenMode);

    u32 track_number = *((u32 *)Data);

    // Call each function with the prepared parameters
    gf_isom_reset_data_offset(iso_file, &top_box_start);

    gf_isom_enable_compression(iso_file, compress_mode, compress_flags);

    gf_isom_reset_switch_parameters(iso_file);

    gf_isom_set_interleave_time(iso_file, interleave_time);

    gf_isom_open_segment(iso_file, "./dummy_file", start_range, end_range, flags);

    gf_isom_rewrite_track_dependencies(iso_file, track_number);

    gf_isom_close(iso_file);

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

        LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    