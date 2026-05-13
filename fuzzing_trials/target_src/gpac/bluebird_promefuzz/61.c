#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* initialize_iso_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);

    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_61(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return 0;

    GF_ISOFile *isom_file = initialize_iso_file(Data, Size);
    if (!isom_file) return 0;

    u32 trackNumber = *(u32*)(Data);
    u32 editIndex = *(u32*)(Data + sizeof(u32));
    u32 chunkNumber = *(u32*)(Data + 2 * sizeof(u32));

    u64 editTime = 0, segmentDuration = 0, mediaTime = 0;
    GF_ISOEditType editMode;
    gf_isom_get_edit(isom_file, trackNumber, editIndex, &editTime, &segmentDuration, &mediaTime, &editMode);

    u64 chunk_offset = 0;
    u32 first_sample_num = 0, sample_per_chunk = 0, sample_desc_idx = 0;
    u32 cache_1 = 0, cache_2 = 0;
    gf_isom_get_chunk_info(isom_file, trackNumber, chunkNumber, &chunk_offset, &first_sample_num, &sample_per_chunk, &sample_desc_idx, &cache_1, &cache_2);

    u64 creationTime = 0, modificationTime = 0;
    gf_isom_get_track_creation_time(isom_file, trackNumber, &creationTime, &modificationTime);

    u32 movieTime = *(u32*)(Data + 3 * sizeof(u32));
    u64 mediaTimeResult = 0;
    gf_isom_get_media_time(isom_file, trackNumber, movieTime, &mediaTimeResult);

    u64 sidx_dur = 0;
    u32 sidx_timescale = 0;
    gf_isom_get_sidx_duration(isom_file, &sidx_dur, &sidx_timescale);

    u64 magic = *(u64*)(Data + 4 * sizeof(u32));
    gf_isom_set_track_magic(isom_file, trackNumber, magic);

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

    LLVMFuzzerTestOneInput_61(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
