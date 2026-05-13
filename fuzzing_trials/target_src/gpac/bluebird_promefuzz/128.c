#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_128(const uint8_t *Data, size_t Size) {
    if (Size < 3 * sizeof(u32)) {
        return 0;
    }

    // Prepare the environment
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    u32 trackNumber = *((u32 *)(Data));
    u32 sampleDescriptionIndex = *((u32 *)(Data + sizeof(u32)));
    GF_ISOTrackID trackID = *((GF_ISOTrackID *)(Data + 2 * sizeof(u32)));

    // Write a dummy file
    write_dummy_file(Data, Size);

    // Test gf_isom_get_track_id
    GF_ISOTrackID track_id = gf_isom_get_track_id(isom_file, trackNumber);
    (void)track_id;

    // Test gf_isom_get_media_subtype
    u32 media_subtype = gf_isom_get_media_subtype(isom_file, trackNumber, sampleDescriptionIndex);
    (void)media_subtype;

    // Test gf_isom_get_udta_count
    u32 udta_count = gf_isom_get_udta_count(isom_file, trackNumber);
    (void)udta_count;

    // Test gf_isom_find_od_id_for_track
    u32 od_id = gf_isom_find_od_id_for_track(isom_file, trackNumber);
    (void)od_id;

    // Test gf_isom_get_vvc_type
    GF_ISOMVVCType vvc_type = gf_isom_get_vvc_type(isom_file, trackNumber, sampleDescriptionIndex);
    (void)vvc_type;

    // Test gf_isom_get_track_by_id
    u32 track_by_id = gf_isom_get_track_by_id(isom_file, trackID);
    (void)track_by_id;

    // Cleanup
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

    LLVMFuzzerTestOneInput_128(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
