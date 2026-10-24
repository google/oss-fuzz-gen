#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* initialize_iso_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return NULL;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return iso_file;
}

int LLVMFuzzerTestOneInput_132(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    GF_ISOFile *iso_file = initialize_iso_file(Data, Size);
    if (!iso_file) {
        return 0;
    }

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


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gf_isom_get_meta_type to gf_isom_get_sample_dts
    // Ensure dataflow is valid (i.e., non-null)
    if (!iso_file) {
    	return 0;
    }
    u32 ret_gf_isom_get_next_alternate_group_id_osbuc = gf_isom_get_next_alternate_group_id(iso_file);
    u32 ret_gf_isom_get_num_supported_boxes_vyals = gf_isom_get_num_supported_boxes();
    // Ensure dataflow is valid (i.e., non-null)
    if (!iso_file) {
    	return 0;
    }
    u64 ret_gf_isom_get_sample_dts_iesia = gf_isom_get_sample_dts(iso_file, ret_gf_isom_get_next_alternate_group_id_osbuc, ret_gf_isom_get_num_supported_boxes_vyals);
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_132(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
