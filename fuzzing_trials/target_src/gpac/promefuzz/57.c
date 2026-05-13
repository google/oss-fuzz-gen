// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_set_media_type at isom_write.c:6188:8 in isomedia.h
// gf_isom_set_sample_cenc_group at isom_write.c:7824:8 in isomedia.h
// gf_isom_remove_user_data_item at isom_write.c:3705:8 in isomedia.h
// gf_isom_get_raw_user_data at isom_write.c:4070:8 in isomedia.h
// gf_isom_append_sample_data at isom_write.c:1218:8 in isomedia.h
// gf_isom_load_extra_boxes at isom_write.c:603:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void initialize_isofile(GF_ISOFile **isom_file) {
    *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
}

static void cleanup_isofile(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_57(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = NULL;
    initialize_isofile(&isom_file);
    if (!isom_file) return 0;

    // Fuzzing gf_isom_set_media_type
    if (Size >= 8) {
        u32 trackNumber = *(const u32 *)Data;
        u32 new_type = *(const u32 *)(Data + 4);
        gf_isom_set_media_type(isom_file, trackNumber, new_type);
    }

    // Fuzzing gf_isom_set_sample_cenc_group
    if (Size >= 19) {
        u32 trackNumber = *(const u32 *)Data;
        u32 sampleNumber = *(const u32 *)(Data + 4);
        u8 isEncrypted = *(const u8 *)(Data + 8);
        u32 crypt_byte_block = *(const u32 *)(Data + 9);
        u32 skip_byte_block = *(const u32 *)(Data + 13);
        u8 *key_info = (u8 *)(Data + 17);
        u32 key_info_size = (Size - 17) > 19 ? 19 : (Size - 17);
        gf_isom_set_sample_cenc_group(isom_file, trackNumber, sampleNumber, isEncrypted, crypt_byte_block, skip_byte_block, key_info, key_info_size);
    }

    // Fuzzing gf_isom_remove_user_data_item
    if (Size >= 24) {
        u32 trackNumber = *(const u32 *)Data;
        u32 UserDataType = *(const u32 *)(Data + 4);
        bin128 UUID;
        memcpy(UUID, Data + 8, sizeof(bin128));
        u32 UserDataIndex = *(const u32 *)(Data + 24);
        gf_isom_remove_user_data_item(isom_file, trackNumber, UserDataType, UUID, UserDataIndex);
    }

    // Fuzzing gf_isom_get_raw_user_data
    u8 *output = NULL;
    u32 output_size = 0;
    gf_isom_get_raw_user_data(isom_file, &output, &output_size);
    if (output) {
        free(output);
    }

    // Fuzzing gf_isom_append_sample_data
    if (Size >= 8) {
        u32 trackNumber = *(const u32 *)Data;
        u8 *data = (u8 *)(Data + 4);
        u32 data_size = Size - 4;
        gf_isom_append_sample_data(isom_file, trackNumber, data, data_size);
    }

    // Fuzzing gf_isom_load_extra_boxes
    if (Size >= 5) {
        u8 *moov_boxes = (u8 *)Data;
        u32 moov_boxes_size = Size;
        Bool udta_only = (Bool)(Data[Size - 1] % 2);
        gf_isom_load_extra_boxes(isom_file, moov_boxes, moov_boxes_size, udta_only);
    }

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

        LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    