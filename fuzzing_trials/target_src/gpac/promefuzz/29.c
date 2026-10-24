// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_cenc_set_pssh at drm_sample.c:886:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_set_cenc_protection at drm_sample.c:758:8 in isomedia.h
// gf_isom_get_pssh_info at isom_read.c:5611:8 in isomedia.h
// gf_isom_add_user_data at isom_write.c:3803:8 in isomedia.h
// gf_isom_get_track_template at isom_write.c:4137:8 in isomedia.h
// gf_isom_get_reference at isom_read.c:1237:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Create a dummy ISO file structure
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return isom_file;
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    // Prepare dummy ISO file
    GF_ISOFile *isom_file = create_dummy_iso_file();
    if (!isom_file) return 0;

    // Fuzz gf_isom_set_cenc_protection
    if (Size > 20) {
        u32 trackNumber = *((u32*)(Data));
        u32 sampleDescriptionIndex = *((u32*)(Data + 4));
        u32 scheme_type = *((u32*)(Data + 8));
        u32 scheme_version = *((u32*)(Data + 12));
        u32 default_IsEncrypted = *((u32*)(Data + 16));
        u32 default_crypt_byte_block = 1;
        u32 default_skip_byte_block = 1;
        u8 *key_info = (u8 *)(Data + 20);
        u32 key_info_size = (Size - 20) > 16 ? 16 : (Size - 20);

        gf_isom_set_cenc_protection(isom_file, trackNumber, sampleDescriptionIndex, scheme_type, scheme_version,
                                    default_IsEncrypted, default_crypt_byte_block, default_skip_byte_block,
                                    key_info, key_info_size);
    }

    // Fuzz gf_isom_get_pssh_info
    if (Size > 4) {
        u32 pssh_index = *((u32*)(Data));
        bin128 SystemID;
        u32 version;
        u32 KID_count;
        const bin128 *KIDs;
        const u8 *private_data;
        u32 private_data_size;

        gf_isom_get_pssh_info(isom_file, pssh_index, SystemID, &version, &KID_count, &KIDs, &private_data, &private_data_size);
    }

    // Fuzz gf_isom_add_user_data
    if (Size > 36) {
        u32 trackNumber = *((u32*)(Data));
        u32 UserDataType = *((u32*)(Data + 4));
        bin128 UUID;
        memcpy(UUID, Data + 8, 16);
        u8 *data = (u8 *)(Data + 24);
        u32 data_size = (Size - 24) > 12 ? 12 : (Size - 24);

        gf_isom_add_user_data(isom_file, trackNumber, UserDataType, UUID, data, data_size);
    }

    // Fuzz gf_isom_get_track_template
    if (Size > 4) {
        u32 trackNumber = *((u32*)(Data));
        u8 *output = NULL;
        u32 output_size = 0;

        gf_isom_get_track_template(isom_file, trackNumber, &output, &output_size);
        if (output) {
            free(output);
        }
    }

    // Fuzz gf_isom_get_reference
    if (Size > 12) {
        u32 trackNumber = *((u32*)(Data));
        u32 referenceType = *((u32*)(Data + 4));
        u32 referenceIndex = *((u32*)(Data + 8));
        u32 refTrack;

        gf_isom_get_reference(isom_file, trackNumber, referenceType, referenceIndex, &refTrack);
    }

    // Fuzz gf_isom_cenc_set_pssh
    if (Size > 24) {
        bin128 systemID;
        memcpy(systemID, Data, 16);
        u32 version = *((u32*)(Data + 16));
        u32 KID_count = *((u32*)(Data + 20));
        bin128 *KID = (bin128 *)(Data + 24);
        u8 *data = (u8 *)(Data + 24 + (KID_count * sizeof(bin128)));
        u32 len = (Size - (24 + (KID_count * sizeof(bin128)))) > 8 ? 8 : (Size - (24 + (KID_count * sizeof(bin128))));
        u32 pssh_mode = 0;

        gf_isom_cenc_set_pssh(isom_file, systemID, version, KID_count, KID, data, len, pssh_mode);
    }

    // Cleanup
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

        LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    