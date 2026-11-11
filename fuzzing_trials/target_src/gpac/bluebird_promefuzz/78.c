#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile *create_dummy_iso_file() {
    // Since GF_ISOFile is an incomplete type, we cannot allocate it directly.
    // We assume there is a function to create or open an ISO file.
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return iso_file;
}

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_78(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) * 7 + sizeof(u32) * 2 + sizeof(GF_ISOEditType)) return 0;

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    write_dummy_file(Data, Size);

    u32 trackNumber = *(u32 *)(Data);
    u64 decode_traf_time = *(u64 *)(Data + sizeof(u32));
    u64 traf_duration = *(u64 *)(Data + sizeof(u32) + sizeof(u64));
    u64 EditDuration = *(u64 *)(Data + sizeof(u32) + sizeof(u64) * 2);
    u64 MediaTime = *(u64 *)(Data + sizeof(u32) + sizeof(u64) * 3);
    GF_ISOEditType EditMode = *(GF_ISOEditType *)(Data + sizeof(u32) + sizeof(u64) * 4);
    u32 edit_index = *(u32 *)(Data + sizeof(u32) + sizeof(u64) * 4 + sizeof(GF_ISOEditType));
    u64 next_dts = *(u64 *)(Data + sizeof(u32) + sizeof(u64) * 4 + sizeof(GF_ISOEditType) + sizeof(u32));
    u64 create_time = *(u64 *)(Data + sizeof(u32) + sizeof(u64) * 5 + sizeof(GF_ISOEditType) + sizeof(u32));
    u64 modif_time = *(u64 *)(Data + sizeof(u32) + sizeof(u64) * 6 + sizeof(GF_ISOEditType) + sizeof(u32));

    gf_isom_set_traf_mss_timeext(iso_file, trackNumber, decode_traf_time, traf_duration);
    gf_isom_append_edit(iso_file, trackNumber, EditDuration, MediaTime, EditMode);
    gf_isom_modify_edit(iso_file, trackNumber, edit_index, EditDuration, MediaTime, EditMode);
    gf_isom_set_traf_base_media_decode_time(iso_file, trackNumber, decode_traf_time);
    gf_isom_patch_last_sample_duration(iso_file, trackNumber, next_dts);
    gf_isom_set_media_creation_time(iso_file, trackNumber, create_time, modif_time);

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

    LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
