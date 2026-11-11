// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_meta_add_item_ref at meta.c:2005:8 in isomedia.h
// gf_isom_set_meta_primary_item at meta.c:1987:8 in isomedia.h
// gf_isom_set_meta_type at meta.c:612:8 in isomedia.h
// gf_isom_meta_add_item_group at meta.c:2137:8 in isomedia.h
// gf_isom_remove_meta_xml at meta.c:678:8 in isomedia.h
// gf_isom_update_aperture_info at isom_write.c:2179:8 in isomedia.h
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

int LLVMFuzzerTestOneInput_124(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 8 + sizeof(Bool) + sizeof(u64)) {
        return 0;
    }

    // Create a dummy GF_ISOFile for fuzzing purposes
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    u32 offset = 0;
    Bool root_meta = (Bool)Data[offset++];
    u32 track_num = *(u32 *)(Data + offset); offset += sizeof(u32);
    u32 from_id = *(u32 *)(Data + offset); offset += sizeof(u32);
    u32 to_id = *(u32 *)(Data + offset); offset += sizeof(u32);
    u32 type = *(u32 *)(Data + offset); offset += sizeof(u32);
    u64 ref_index = 0;

    // Fuzz gf_isom_meta_add_item_ref
    gf_isom_meta_add_item_ref(isom_file, root_meta, track_num, from_id, to_id, type, &ref_index);

    u32 item_num = *(u32 *)(Data + offset); offset += sizeof(u32);

    // Fuzz gf_isom_set_meta_primary_item
    gf_isom_set_meta_primary_item(isom_file, root_meta, track_num, item_num);

    u32 metaType = *(u32 *)(Data + offset); offset += sizeof(u32);

    // Fuzz gf_isom_set_meta_type
    gf_isom_set_meta_type(isom_file, root_meta, track_num, metaType);

    u32 item_id = *(u32 *)(Data + offset); offset += sizeof(u32);
    u32 group_id = *(u32 *)(Data + offset); offset += sizeof(u32);
    u32 group_type = *(u32 *)(Data + offset); offset += sizeof(u32);

    // Fuzz gf_isom_meta_add_item_group
    gf_isom_meta_add_item_group(isom_file, root_meta, track_num, item_id, group_id, group_type);

    // Fuzz gf_isom_remove_meta_xml
    gf_isom_remove_meta_xml(isom_file, root_meta, track_num);

    Bool remove = (Bool)Data[offset++];

    // Fuzz gf_isom_update_aperture_info
    gf_isom_update_aperture_info(isom_file, track_num, remove);

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

        LLVMFuzzerTestOneInput_124(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    