// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_get_edit at isom_read.c:2560:8 in isomedia.h
// gf_isom_get_chunk_info at isom_read.c:6325:8 in isomedia.h
// gf_isom_get_track_creation_time at isom_read.c:1004:8 in isomedia.h
// gf_isom_get_media_time at isom_read.c:1342:8 in isomedia.h
// gf_isom_get_sidx_duration at isom_read.c:6196:8 in isomedia.h
// gf_isom_set_track_magic at isom_write.c:8936:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* initialize_isofile(const uint8_t *Data, size_t Size) {
    // Assuming GF_ISOFile is initialized through a library function
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return NULL;

    // Simulate writing data to a file
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
    return isom_file;
}

static void cleanup_isofile(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_206(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3 + sizeof(u64) * 4) return 0;

    GF_ISOFile *isom_file = initialize_isofile(Data, Size);
    if (!isom_file) return 0;

    u32 trackNumber = *(u32 *)Data;
    u32 EditIndex = *(u32 *)(Data + sizeof(u32));
    u32 chunkNumber = *(u32 *)(Data + sizeof(u32) * 2);

    u64 EditTime, SegmentDuration, MediaTime;
    GF_ISOEditType EditMode;

    gf_isom_get_edit(isom_file, trackNumber, EditIndex, &EditTime, &SegmentDuration, &MediaTime, &EditMode);

    u64 chunk_offset;
    u32 first_sample_num, sample_per_chunk, sample_desc_idx, cache_1 = 0, cache_2 = 0;
    gf_isom_get_chunk_info(isom_file, trackNumber, chunkNumber, &chunk_offset, &first_sample_num, &sample_per_chunk, &sample_desc_idx, &cache_1, &cache_2);

    u64 creationTime, modificationTime;
    gf_isom_get_track_creation_time(isom_file, trackNumber, &creationTime, &modificationTime);

    u32 movieTime = *(u32 *)(Data + sizeof(u32) * 3);
    u64 mediaTime;
    gf_isom_get_media_time(isom_file, trackNumber, movieTime, &mediaTime);

    u64 sidx_dur;
    u32 sidx_timescale;
    gf_isom_get_sidx_duration(isom_file, &sidx_dur, &sidx_timescale);

    u64 magic = *(u64 *)(Data + sizeof(u32) * 3 + sizeof(u64));
    gf_isom_set_track_magic(isom_file, trackNumber, magic);

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

        LLVMFuzzerTestOneInput_206(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    