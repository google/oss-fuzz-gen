// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_set_media_type at isom_write.c:6188:8 in isomedia.h
// gf_isom_svc_config_del at avc_ext.c:1818:8 in isomedia.h
// gf_isom_remove_track_from_root_od at isom_write.c:179:8 in isomedia.h
// gf_isom_add_track_to_root_od at isom_write.c:136:8 in isomedia.h
// gf_isom_set_write_callback at isom_intern.c:1104:8 in isomedia.h
// gf_isom_remove_track_references at isom_write.c:5036:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_Err dummy_on_block_out(void *usr_data, u8 *block, u32 block_size, void *cbk_data, u32 cbk_magic) {
    return GF_OK;
}

static GF_Err dummy_on_block_patch(void *usr_data, u8 *block, u32 block_size, u64 block_offset, Bool is_insert) {
    return GF_OK;
}

static void dummy_on_last_block_start(void *usr_data) {
    // Do nothing
}

int LLVMFuzzerTestOneInput_232(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) {
        return 0;
    }

    // Allocate memory for the GF_ISOFile structure using a dummy size
    GF_ISOFile *isom_file = (GF_ISOFile *)malloc(1024);
    if (!isom_file) {
        return 0;
    }
    memset(isom_file, 0, 1024);

    u32 trackNumber = *((u32 *)Data);
    u32 new_type = *((u32 *)(Data + sizeof(u32)));
    u32 sampleDescriptionIndex = *((u32 *)(Data + 2 * sizeof(u32)));

    // Fuzz gf_isom_set_media_type
    gf_isom_set_media_type(isom_file, trackNumber, new_type);

    // Fuzz gf_isom_svc_config_del
    gf_isom_svc_config_del(isom_file, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_remove_track_from_root_od
    gf_isom_remove_track_from_root_od(isom_file, trackNumber);

    // Fuzz gf_isom_add_track_to_root_od
    gf_isom_add_track_to_root_od(isom_file, trackNumber);

    // Fuzz gf_isom_set_write_callback
    gf_isom_set_write_callback(isom_file, dummy_on_block_out, dummy_on_block_patch, dummy_on_last_block_start, NULL, new_type);

    // Fuzz gf_isom_remove_track_references
    gf_isom_remove_track_references(isom_file, trackNumber);

    free(isom_file);
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

        LLVMFuzzerTestOneInput_232(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    