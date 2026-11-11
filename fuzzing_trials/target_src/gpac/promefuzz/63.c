// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_add_meta_item_sample_ref at meta.c:1806:8 in isomedia.h
// gf_isom_add_meta_item2 at meta.c:1792:8 in isomedia.h
// gf_isom_get_meta_item_info at meta.c:131:8 in isomedia.h
// gf_isom_extract_meta_xml at meta.c:68:8 in isomedia.h
// gf_isom_remove_meta_item at meta.c:1879:8 in isomedia.h
// gf_isom_extract_meta_item at meta.c:494:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Write the fuzz data to a dummy file
    write_dummy_file(Data, Size);

    // Open the ISO file
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!isom_file) return 0;

    Bool root_meta = Data[0] % 2;
    u32 track_num = (Size > 1) ? Data[1] : 0;
    const char *item_name = "item_name";
    u32 item_id = 0;
    u32 item_type = 'test';
    const char *mime_type = "application/test";
    const char *content_encoding = NULL;
    GF_ImageItemProperties *image_props = NULL;
    GF_ISOTrackID tk_id = 1;
    u32 sample_num = 1;
    GF_Err err;

    const char *resource_path = "./dummy_file";
    Bool self_reference = GF_FALSE;
    u32 io_item_id = 0;
    const char *URL = NULL;
    const char *URN = NULL;

    // Test gf_isom_add_meta_item_sample_ref
    err = gf_isom_add_meta_item_sample_ref(isom_file, root_meta, track_num, item_name, &item_id, item_type,
                                           mime_type, content_encoding, image_props, tk_id, sample_num);

    // Test gf_isom_add_meta_item2
    err = gf_isom_add_meta_item2(isom_file, root_meta, track_num, self_reference, (char *)resource_path, item_name,
                                 &io_item_id, item_type, mime_type, content_encoding, URL, URN, image_props);

    // Test gf_isom_get_meta_item_info
    u32 itemID, type, protection_scheme, protection_scheme_version;
    Bool is_self_reference;
    const char *item_name_out, *item_mime_type, *item_encoding, *item_url, *item_urn;
    err = gf_isom_get_meta_item_info(isom_file, root_meta, track_num, 1, &itemID, &type, &protection_scheme,
                                     &protection_scheme_version, &is_self_reference, &item_name_out, &item_mime_type,
                                     &item_encoding, &item_url, &item_urn);

    // Test gf_isom_extract_meta_xml
    Bool is_binary;
    err = gf_isom_extract_meta_xml(isom_file, root_meta, track_num, (char *)"./dummy_file", &is_binary);

    // Test gf_isom_remove_meta_item
    err = gf_isom_remove_meta_item(isom_file, root_meta, track_num, 1, GF_FALSE, NULL);

    // Test gf_isom_extract_meta_item
    err = gf_isom_extract_meta_item(isom_file, root_meta, track_num, 1, "./dummy_file");

    // Clean up
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

        LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    