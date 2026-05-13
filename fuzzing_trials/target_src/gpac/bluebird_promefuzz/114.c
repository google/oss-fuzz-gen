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

#define DUMMY_FILE_PATH "./dummy_file"

// Dummy implementation of GF_ISOFile for fuzzing purposes
struct DummyISOFile {
    char dummy_data[256]; // Arbitrary size for dummy data
};

static GF_ISOFile* create_dummy_iso_file() {
    // Allocate memory for the DummyISOFile
    struct DummyISOFile *iso_file = (struct DummyISOFile *)malloc(sizeof(struct DummyISOFile));
    if (!iso_file) return NULL;
    memset(iso_file, 0, sizeof(struct DummyISOFile));
    return (GF_ISOFile *)iso_file;
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        free(iso_file);
    }
}

int LLVMFuzzerTestOneInput_114(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 2 + sizeof(Bool)) return 0;

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = *(u32 *)Data;
    Data += sizeof(u32);
    Size -= sizeof(u32);

    Bool flag = *(Bool *)Data;
    Data += sizeof(Bool);
    Size -= sizeof(Bool);

    // Fuzz gf_isom_set_track_enabled
    gf_isom_set_track_enabled(iso_file, trackNumber, flag);

    // Fuzz gf_isom_reset_track_switch_parameter
    gf_isom_reset_track_switch_parameter(iso_file, trackNumber, flag);

    // Fuzz gf_isom_set_cts_packing
    gf_isom_set_cts_packing(iso_file, trackNumber, flag);

    // Fuzz gf_isom_use_compact_size
    gf_isom_use_compact_size(iso_file, trackNumber, flag);

    if (Size < sizeof(u32) * 2 + sizeof(Bool)) {
        cleanup_iso_file(iso_file);
        return 0;
    }

    u32 track_group_id = *(u32 *)Data;
    Data += sizeof(u32);
    Size -= sizeof(u32);

    u32 group_type = *(u32 *)Data;
    Data += sizeof(u32);
    Size -= sizeof(u32);

    // Fuzz gf_isom_set_track_group
    gf_isom_set_track_group(iso_file, trackNumber, track_group_id, group_type, flag);

    if (Size < sizeof(u32) + sizeof(GF_ISOSample) + sizeof(Bool)) {
        cleanup_iso_file(iso_file);
        return 0;
    }

    u32 sampleNumber = *(u32 *)Data;
    Data += sizeof(u32);
    Size -= sizeof(u32);

    GF_ISOSample *sample = (GF_ISOSample *)Data;
    Data += sizeof(GF_ISOSample);
    Size -= sizeof(GF_ISOSample);

    Bool data_only = *(Bool *)Data;

    // Fuzz gf_isom_update_sample
    gf_isom_update_sample(iso_file, trackNumber, sampleNumber, sample, data_only);

    cleanup_iso_file(iso_file);
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

    LLVMFuzzerTestOneInput_114(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
