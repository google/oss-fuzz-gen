#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile *initialize_iso_file(const uint8_t *Data, size_t Size) {
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!iso_file) return NULL;

    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        gf_isom_close(iso_file);
        return NULL;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    return iso_file;
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_163(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile *iso_file = initialize_iso_file(Data, Size);
    if (!iso_file) return 0;

    // Fuzz gf_isom_reset_switch_parameters
    gf_isom_reset_switch_parameters(iso_file);

    // Fuzz gf_isom_release_segment with both true and false
    gf_isom_release_segment(iso_file, 0);
    gf_isom_release_segment(iso_file, 1);

    // Fuzz gf_isom_remove_root_od
    gf_isom_remove_root_od(iso_file);

    // Fuzz gf_isom_flush_fragments with both true and false
    gf_isom_flush_fragments(iso_file, 0);
    gf_isom_flush_fragments(iso_file, 1);

    // Fuzz gf_isom_set_sample_group_in_traf
    gf_isom_set_sample_group_in_traf(iso_file);

    // Fuzz gf_isom_enable_mfra
    gf_isom_enable_mfra(iso_file);

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

    LLVMFuzzerTestOneInput_163(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
