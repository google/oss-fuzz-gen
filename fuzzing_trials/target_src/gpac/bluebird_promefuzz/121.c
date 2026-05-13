#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* initialize_iso_file() {
    // Since GF_ISOFile is an incomplete type, we cannot allocate it directly.
    // Assume we have a function to create or open an ISO file.
    GF_ISOFile *file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return file;
}

static void cleanup_iso_file(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_121(const uint8_t *Data, size_t Size) {
    if (Size < 16) return 0; // Ensure enough data for trackNumber, sampleNumber, nb_samples, edit_index

    GF_ISOFile *isom_file = initialize_iso_file();
    if (!isom_file) return 0;

    u32 trackNumber = *(u32*)Data;
    u32 sampleNumber = *(u32*)(Data + 4);
    u32 nb_samples = *(u32*)(Data + 8);
    u32 edit_index = *(u32*)(Data + 12);

    // Fuzz gf_isom_remove_sample
    gf_isom_remove_sample(isom_file, trackNumber, sampleNumber);

    // Fuzz gf_isom_purge_samples
    gf_isom_purge_samples(isom_file, trackNumber, nb_samples);

    // Fuzz gf_isom_remove_cenc_seig_sample_group
    gf_isom_remove_cenc_seig_sample_group(isom_file, trackNumber);

    // Fuzz gf_isom_remove_edit
    gf_isom_remove_edit(isom_file, trackNumber, edit_index);

    // Fuzz gf_isom_remove_track_references
    gf_isom_remove_track_references(isom_file, trackNumber);

    // Fuzz gf_isom_cenc_allocate_storage
    gf_isom_cenc_allocate_storage(isom_file, trackNumber);

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

    LLVMFuzzerTestOneInput_121(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
