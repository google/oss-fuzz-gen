// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_set_meta_xml at meta.c:698:8 in isomedia.h
// gf_isom_extract_meta_item_mem at meta.c:500:8 in isomedia.h
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

#define DUMMY_FILE "./dummy_file"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_134(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(GF_ISOFile *)) return 0;

    GF_ISOFile *isom_file = gf_isom_open(DUMMY_FILE, GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    // Prepare parameters
    Bool root_meta = GF_TRUE;
    u32 track_num = 0;
    u32 item_id = 1;
    u8 *out_data = NULL;
    u32 out_size = 0;
    u32 out_alloc_size = 0;
    const char *mime_type = NULL;
    Bool use_annex_b = GF_FALSE;
    Bool is_binary = GF_FALSE;
    Bool keep_refs = GF_FALSE;
    const char *keep_props = NULL;

    // Write dummy file for file-based operations
    write_dummy_file(Data, Size);

    // Call gf_isom_set_meta_xml
    gf_isom_set_meta_xml(isom_file, root_meta, track_num, DUMMY_FILE, NULL, 0, is_binary);

    // Call gf_isom_extract_meta_item_mem
    gf_isom_extract_meta_item_mem(isom_file, root_meta, track_num, item_id, &out_data, &out_size, &out_alloc_size, &mime_type, use_annex_b);

    // Call gf_isom_get_meta_item_info
    u32 itemID, type, protection_scheme, protection_scheme_version;
    Bool is_self_reference;
    const char *item_name, *item_mime_type, *item_encoding, *item_url, *item_urn;
    gf_isom_get_meta_item_info(isom_file, root_meta, track_num, item_id, &itemID, &type, &protection_scheme, &protection_scheme_version, &is_self_reference, &item_name, &item_mime_type, &item_encoding, &item_url, &item_urn);

    // Call gf_isom_extract_meta_xml
    gf_isom_extract_meta_xml(isom_file, root_meta, track_num, DUMMY_FILE, &is_binary);

    // Call gf_isom_remove_meta_item
    gf_isom_remove_meta_item(isom_file, root_meta, track_num, item_id, keep_refs, keep_props);

    // Call gf_isom_extract_meta_item
    gf_isom_extract_meta_item(isom_file, root_meta, track_num, item_id, DUMMY_FILE);

    // Free allocated memory
    free(out_data);
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

        LLVMFuzzerTestOneInput_134(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    