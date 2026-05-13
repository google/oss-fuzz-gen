#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* initialize_isofile() {
    // Assuming GF_ISOFile is properly initialized elsewhere in the actual library
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return isom_file;
}

static void cleanup_isofile(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(s64) + sizeof(GF_ISOStorageMode) + sizeof(GF_Fraction)) {
        return 0;
    }

    GF_ISOFile *isom_file = initialize_isofile();
    if (!isom_file) {
        return 0;
    }

    GF_ISOStorageMode storage_mode = *((GF_ISOStorageMode *)Data);
    s64 byte_offset = *((s64 *)(Data + sizeof(GF_ISOStorageMode)));
    GF_Fraction fTimeInSec = *((GF_Fraction *)(Data + sizeof(GF_ISOStorageMode) + sizeof(s64)));

    // Fuzz gf_isom_set_storage_mode
    gf_isom_set_storage_mode(isom_file, storage_mode);

    // Fuzz gf_isom_make_interleave_ex
    gf_isom_make_interleave_ex(isom_file, &fTimeInSec);

    // Fuzz gf_isom_set_byte_offset
    gf_isom_set_byte_offset(isom_file, byte_offset);

    // Fuzz gf_isom_remove_root_od
    gf_isom_remove_root_od(isom_file);

    // Fuzz gf_isom_update_duration
    gf_isom_update_duration(isom_file);

    // Fuzz gf_isom_set_sample_group_in_traf
    gf_isom_set_sample_group_in_traf(isom_file);

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

    LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
