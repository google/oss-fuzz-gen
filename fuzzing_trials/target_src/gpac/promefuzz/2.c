// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_has_meta_xml at meta.c:52:5 in isomedia.h
// gf_isom_get_meta_item_flags at meta.c:207:5 in isomedia.h
// gf_isom_meta_get_item_ref_count at meta.c:2185:5 in isomedia.h
// gf_isom_meta_item_has_ref at meta.c:2203:5 in isomedia.h
// gf_isom_meta_get_item_ref_id at meta.c:2226:5 in isomedia.h
// gf_isom_get_meta_type at meta.c:43:5 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "isomedia.h"

static GF_ISOFile* initialize_iso_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);

    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return iso_file;
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile *iso_file = initialize_iso_file(Data, Size);
    if (!iso_file) return 0;

    Bool root_meta = Data[0] % 2;
    u32 track_num = (Size > 1) ? Data[1] : 0;
    u32 item_num = (Size > 2) ? Data[2] : 1;
    u32 from_id = (Size > 3) ? Data[3] : 1;
    u32 to_id = (Size > 4) ? Data[4] : 1;
    u32 type = (Size > 5) ? Data[5] : 0;
    u32 ref_idx = (Size > 6) ? Data[6] : 1;

    u32 result;

    result = gf_isom_has_meta_xml(iso_file, root_meta, track_num);
    result = gf_isom_get_meta_item_flags(iso_file, root_meta, track_num, item_num);
    result = gf_isom_meta_get_item_ref_count(iso_file, root_meta, track_num, from_id, type);
    result = gf_isom_meta_item_has_ref(iso_file, root_meta, track_num, to_id, type);
    result = gf_isom_meta_get_item_ref_id(iso_file, root_meta, track_num, from_id, type, ref_idx);
    result = gf_isom_get_meta_type(iso_file, root_meta, track_num);

    gf_isom_close(iso_file);
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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    