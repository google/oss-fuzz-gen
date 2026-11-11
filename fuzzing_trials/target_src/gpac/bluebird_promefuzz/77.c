#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Since GF_ISOFile is an incomplete type, we cannot allocate or initialize it directly
    // We assume there is a function to create or open an ISO file in the actual library
    // This is a placeholder for such a function
    GF_ISOFile *file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return file;
}

static void cleanup_iso_file(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = create_dummy_iso_file();
    if (!isom_file) return 0;

    if (Size < sizeof(u32)) {
        cleanup_iso_file(isom_file);
        return 0;
    }

    u32 trackNumber = *(u32 *)Data;
    u32 UserDataType = trackNumber;
    bin128 UUID;
    memset(&UUID, 0, sizeof(bin128));
    u8 *output = NULL;
    u32 output_size = 0;

    // Fuzz gf_isom_is_track_in_root_od
    u8 result = gf_isom_is_track_in_root_od(isom_file, trackNumber);

    // Fuzz gf_isom_get_user_data_count
    u32 userDataCount = gf_isom_get_user_data_count(isom_file, trackNumber, UserDataType, UUID);

    // Fuzz gf_isom_get_trex_template
    GF_Err trexErr = gf_isom_get_trex_template(isom_file, trackNumber, &output, &output_size);
    if (output) free(output);

    // Fuzz gf_isom_is_track_enabled
    u8 trackEnabled = gf_isom_is_track_enabled(isom_file, trackNumber);

    // Fuzz gf_isom_fragment_set_sample_aux_info
    u8 aux_data[16];
    GF_Err auxErr = gf_isom_fragment_set_sample_aux_info(isom_file, trackNumber, 1, 1, 0, aux_data, sizeof(aux_data));

    // Fuzz gf_isom_has_sync_points
    u8 syncPoints = gf_isom_has_sync_points(isom_file, trackNumber);

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

    LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
