// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_extract_meta_item_get_cenc_info at meta.c:506:8 in isomedia.h
// gf_isom_fragment_add_subsample at movie_fragments.c:3133:8 in isomedia.h
// gf_isom_set_cenc_protection at drm_sample.c:758:8 in isomedia.h
// gf_isom_track_cenc_add_sample_info at drm_sample.c:1309:8 in isomedia.h
// gf_isom_get_sample_cenc_info at isom_read.c:5790:8 in isomedia.h
// gf_isom_ismacryp_sample_from_data at drm_sample.c:48:16 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_96(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file(Data, Size);

    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    // Fuzz gf_isom_extract_meta_item_get_cenc_info
    {
        Bool is_protected = GF_FALSE;
        u32 skip_byte_block = 0;
        u32 crypt_byte_block = 0;
        const u8 *key_info = NULL;
        u32 key_info_size = 0;
        u32 aux_info_type_parameter = 0;
        u8 *sai_out_data = NULL;
        u32 sai_out_size = 0;
        u32 sai_out_alloc_size = 0;

        gf_isom_extract_meta_item_get_cenc_info(
            isom_file, GF_FALSE, 0, 1, &is_protected, &skip_byte_block, &crypt_byte_block,
            &key_info, &key_info_size, &aux_info_type_parameter,
            &sai_out_data, &sai_out_size, &sai_out_alloc_size
        );

        free(sai_out_data);
    }

    // Fuzz gf_isom_fragment_add_subsample
    {
        gf_isom_fragment_add_subsample(isom_file, 1, 0, 0, 0, 0, GF_FALSE);
    }

    // Fuzz gf_isom_set_cenc_protection
    {
        u8 key_info[16] = {0};
        gf_isom_set_cenc_protection(isom_file, 1, 1, 0, 1, 0, 0, 0, key_info, sizeof(key_info));
    }

    // Fuzz gf_isom_track_cenc_add_sample_info
    {
        u8 buf[16] = {0};
        gf_isom_track_cenc_add_sample_info(isom_file, 1, 'senc', buf, sizeof(buf), GF_FALSE, GF_FALSE, GF_FALSE);
    }

    // Fuzz gf_isom_get_sample_cenc_info
    {
        Bool IsEncrypted = GF_FALSE;
        u32 crypt_byte_block = 0;
        u32 skip_byte_block = 0;
        const u8 *key_info = NULL;
        u32 key_info_size = 0;

        gf_isom_get_sample_cenc_info(isom_file, 1, 1, &IsEncrypted, &crypt_byte_block, &skip_byte_block, &key_info, &key_info_size);
    }

    // Fuzz gf_isom_ismacryp_sample_from_data
    {
        u8 sample_data[16] = {0};
        GF_ISMASample *sample = gf_isom_ismacryp_sample_from_data(sample_data, sizeof(sample_data), GF_FALSE, 0, 0);
        if (sample) {
            free(sample);
        }
    }

    gf_isom_close(isom_file);
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

        LLVMFuzzerTestOneInput_96(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    