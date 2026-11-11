// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_update_edit_list_duration at isom_write.c:8473:8 in isomedia.h
// gf_isom_set_alternate_group_id at isom_write.c:6981:8 in isomedia.h
// gf_isom_cenc_allocate_storage at drm_sample.c:1142:8 in isomedia.h
// gf_isom_set_root_od_id at isom_write.c:601:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_clone_pl_indications at isom_write.c:4010:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
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

int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t) * 3) return 0;

    write_dummy_file(Data, Size);

    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!isom_file) return 0;

    uint32_t trackNumber = *((uint32_t *)Data);
    uint32_t groupId = *(((uint32_t *)Data) + 1);
    uint32_t OD_ID = *(((uint32_t *)Data) + 2);

    // Fuzz gf_isom_update_edit_list_duration
    gf_isom_update_edit_list_duration(isom_file, trackNumber);

    // Fuzz gf_isom_set_alternate_group_id
    gf_isom_set_alternate_group_id(isom_file, trackNumber, groupId);

    // Fuzz gf_isom_cenc_allocate_storage
    gf_isom_cenc_allocate_storage(isom_file, trackNumber);

    // Fuzz gf_isom_set_root_od_id
    gf_isom_set_root_od_id(isom_file, OD_ID);

    GF_ISOFile *dest_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (dest_file) {
        // Fuzz gf_isom_clone_pl_indications
        gf_isom_clone_pl_indications(isom_file, dest_file);
        gf_isom_close(dest_file);
    }

    // Fuzz gf_isom_close
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

        LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    