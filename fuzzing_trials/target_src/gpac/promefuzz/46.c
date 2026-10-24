// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_get_fragmented_duration at isom_read.c:5409:5 in isomedia.h
// gf_isom_get_original_duration at isom_read.c:986:5 in isomedia.h
// gf_isom_get_duration at isom_read.c:971:5 in isomedia.h
// gf_isom_get_track_duration at isom_read.c:1076:5 in isomedia.h
// gf_isom_get_smooth_next_tfdt at isom_read.c:5835:5 in isomedia.h
// gf_isom_get_media_duration at isom_read.c:1426:5 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_isofile_from_data(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return NULL;

    // Simulate reading data into the isom_file structure
    // In reality, you would parse the Data into the structure
    // Here we assume the file operations are abstracted by the library
    return isom_file;
}

static void cleanup_isofile(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size) {
    // Create a dummy file to simulate file input
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    GF_ISOFile *isom_file = create_isofile_from_data(Data, Size);
    if (!isom_file) return 0;

    // Test gf_isom_get_fragmented_duration
    u64 frag_duration = gf_isom_get_fragmented_duration(isom_file);
    (void)frag_duration; // Use the result or log it if necessary

    // Test gf_isom_get_original_duration
    u64 orig_duration = gf_isom_get_original_duration(isom_file);
    (void)orig_duration; // Use the result or log it if necessary

    // Test gf_isom_get_duration
    u64 duration = gf_isom_get_duration(isom_file);
    (void)duration; // Use the result or log it if necessary

    // Test gf_isom_get_track_duration
    if (Size >= sizeof(u32)) {
        u32 track_number = *(u32*)Data;
        u64 track_duration = gf_isom_get_track_duration(isom_file, track_number);
        (void)track_duration; // Use the result or log it if necessary
    }

    // Test gf_isom_get_smooth_next_tfdt
    if (Size >= sizeof(u32) * 2) {
        u32 track_number = *(u32*)(Data + sizeof(u32));
        u64 next_tfdt = gf_isom_get_smooth_next_tfdt(isom_file, track_number);
        (void)next_tfdt; // Use the result or log it if necessary
    }

    // Test gf_isom_get_media_duration
    if (Size >= sizeof(u32) * 3) {
        u32 track_number = *(u32*)(Data + sizeof(u32) * 2);
        u64 media_duration = gf_isom_get_media_duration(isom_file, track_number);
        (void)media_duration; // Use the result or log it if necessary
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

        LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    