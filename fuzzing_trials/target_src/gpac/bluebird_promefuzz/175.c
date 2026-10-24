#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

#define DUMMY_FILE_NAME "./dummy_file"

// Dummy structure size definition
#define DUMMY_ISOFILE_SIZE 512

static GF_ISOFile* create_dummy_isofile() {
    // Allocate memory for the GF_ISOFile structure
    GF_ISOFile* isom_file = (GF_ISOFile*)malloc(DUMMY_ISOFILE_SIZE);
    if (!isom_file) return NULL;
    memset(isom_file, 0, DUMMY_ISOFILE_SIZE);
    return isom_file;
}

static void cleanup_dummy_isofile(GF_ISOFile* isom_file) {
    if (isom_file) {
        free(isom_file);
    }
}

int LLVMFuzzerTestOneInput_175(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    // Test gf_isom_set_meta_xml
    {
        char *xml_file_name = NULL;
        unsigned char *data = NULL;
        u32 data_size = 0;
        Bool is_binary_xml = GF_FALSE;
        
        if (Size > 1) {
            xml_file_name = DUMMY_FILE_NAME;
            FILE *file = fopen(DUMMY_FILE_NAME, "wb");
            if (file) {
                fwrite(Data, 1, Size, file);
                fclose(file);
            }
        } else {
            data = (unsigned char *)Data;
            data_size = (u32)Size;
        }

        gf_isom_set_meta_xml(isom_file, GF_TRUE, 0, xml_file_name, data, data_size, is_binary_xml);
    }

    // Test gf_isom_force_64bit_chunk_offset
    {
        Bool set_on = (Bool)(Data[0] % 2);
        gf_isom_force_64bit_chunk_offset(isom_file, set_on);
    }

    // Test gf_isom_set_meta_primary_item
    {
        u32 track_num = 0;
        u32 item_num = 1;
        gf_isom_set_meta_primary_item(isom_file, GF_FALSE, track_num, item_num);
    }

    // Test gf_isom_reset_alt_brands_ex
    {
        Bool leave_empty = (Bool)(Data[0] % 2);
        gf_isom_reset_alt_brands_ex(isom_file, leave_empty);
    }

    // Test gf_isom_disable_brand_rewrite
    {
        Bool do_disable = (Bool)(Data[0] % 2);
        gf_isom_disable_brand_rewrite(isom_file, do_disable);
    }

    // Test gf_isom_update_aperture_info
    {
        u32 trackNumber = 0;
        Bool remove = (Bool)(Data[0] % 2);
        gf_isom_update_aperture_info(isom_file, trackNumber, remove);
    }

    cleanup_dummy_isofile(isom_file);
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

    LLVMFuzzerTestOneInput_175(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
