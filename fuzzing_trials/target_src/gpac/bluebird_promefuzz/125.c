#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* initialize_iso_file() {
    // Assuming GF_ISOFile is initialized through a specific function
    GF_ISOFile *file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return file;
}

static void cleanup_iso_file(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_125(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3 + sizeof(u64) * 3 + sizeof(GF_ISOEditType) + sizeof(u32)) {
        return 0;
    }

    GF_ISOFile *isoFile = initialize_iso_file();
    if (!isoFile) return 0;

    u32 trackNumber = *((u32 *)Data);
    u32 editIndex = *((u32 *)(Data + sizeof(u32)));
    u64 editDuration = *((u64 *)(Data + sizeof(u32) * 2));
    u64 mediaTime = *((u64 *)(Data + sizeof(u32) * 2 + sizeof(u64)));
    GF_ISOEditType editMode = *((GF_ISOEditType *)(Data + sizeof(u32) * 2 + sizeof(u64) * 2));
    u64 editTime = *((u64 *)(Data + sizeof(u32) * 2 + sizeof(u64) * 2 + sizeof(GF_ISOEditType)));
    u32 mediaRate = *((u32 *)(Data + sizeof(u32) * 2 + sizeof(u64) * 3 + sizeof(GF_ISOEditType)));

    // Ensure trackDuration does not read out of bounds
    if (Size >= sizeof(u32) * 3 + sizeof(u64) * 3 + sizeof(GF_ISOEditType) + sizeof(u64)) {
        u64 trackDuration = *((u64 *)(Data + sizeof(u32) * 3 + sizeof(u64) * 3 + sizeof(GF_ISOEditType)));

        // Fuzzing gf_isom_force_track_duration
        gf_isom_force_track_duration(isoFile, trackNumber, trackDuration);
    }

    u64 outEditTime, outSegmentDuration, outMediaTime;
    GF_ISOEditType outEditMode;

    // Fuzzing gf_isom_append_edit
    gf_isom_append_edit(isoFile, trackNumber, editDuration, mediaTime, editMode);

    // Fuzzing gf_isom_get_edit
    gf_isom_get_edit(isoFile, trackNumber, editIndex, &outEditTime, &outSegmentDuration, &outMediaTime, &outEditMode);

    // Fuzzing gf_isom_modify_edit
    gf_isom_modify_edit(isoFile, trackNumber, editIndex, editDuration, mediaTime, editMode);

    // Fuzzing gf_isom_set_edit_with_rate
    gf_isom_set_edit_with_rate(isoFile, trackNumber, editTime, editDuration, mediaTime, mediaRate);

    // Fuzzing gf_isom_set_edit
    gf_isom_set_edit(isoFile, trackNumber, editTime, editDuration, mediaTime, editMode);

    cleanup_iso_file(isoFile);
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

    LLVMFuzzerTestOneInput_125(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
