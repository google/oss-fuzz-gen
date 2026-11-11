// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_enable_mfra at movie_fragments.c:3465:8 in isomedia.h
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_force_64bit_chunk_offset at isom_write.c:2788:8 in isomedia.h
// gf_isom_set_byte_offset at isom_read.c:5910:8 in isomedia.h
// gf_isom_freeze_order at isom_read.c:76:8 in isomedia.h
// gf_isom_remove_root_od at isom_write.c:165:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(s64) + sizeof(Bool)) return 0;

    // Create a dummy file for testing
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (!dummy_file) return 0;
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    // Open the ISO file
    GF_ISOFile* isofile = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isofile) return 0;

    // Fuzz gf_isom_enable_mfra
    gf_isom_enable_mfra(isofile);

    // Fuzz gf_isom_reset_sample_count
    gf_isom_reset_sample_count(isofile);

    // Fuzz gf_isom_force_64bit_chunk_offset
    Bool set_on = Data[0] % 2; // Randomly choose GF_TRUE or GF_FALSE
    gf_isom_force_64bit_chunk_offset(isofile, set_on);

    // Fuzz gf_isom_set_byte_offset
    s64 byte_offset = *((s64*)(Data + sizeof(Bool)));
    gf_isom_set_byte_offset(isofile, byte_offset);

    // Fuzz gf_isom_freeze_order
    gf_isom_freeze_order(isofile);

    // Fuzz gf_isom_remove_root_od
    gf_isom_remove_root_od(isofile);

    gf_isom_close(isofile);
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
    