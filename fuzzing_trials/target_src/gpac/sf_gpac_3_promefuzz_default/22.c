// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_set_timescale at isom_write.c:451:8 in isomedia.h
// gf_isom_update_edit_list_duration at isom_write.c:8473:8 in isomedia.h
// gf_isom_set_alternate_group_id at isom_write.c:6981:8 in isomedia.h
// gf_isom_set_root_od_id at isom_write.c:601:8 in isomedia.h
// gf_isom_clone_pl_indications at isom_write.c:4010:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    GF_ISOFile* iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!iso_file) return NULL;
    return iso_file;
}

static void destroy_dummy_iso_file(GF_ISOFile* iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size < 16) return 0; // Ensure there's enough data to read u32 values

    GF_ISOFile* iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 timeScale = *((u32*)Data);
    u32 trackNumber = *((u32*)(Data + 4));
    u32 groupId = *((u32*)(Data + 8));
    u32 OD_ID = *((u32*)(Data + 12));

    // Test gf_isom_set_timescale
    gf_isom_set_timescale(iso_file, timeScale);

    // Test gf_isom_update_edit_list_duration
    gf_isom_update_edit_list_duration(iso_file, trackNumber);

    // Test gf_isom_set_alternate_group_id
    gf_isom_set_alternate_group_id(iso_file, trackNumber, groupId);

    // Test gf_isom_set_root_od_id
    gf_isom_set_root_od_id(iso_file, OD_ID);

    // Create another dummy ISO file for cloning
    GF_ISOFile* dest_file = create_dummy_iso_file();
    if (dest_file) {
        // Test gf_isom_clone_pl_indications
        gf_isom_clone_pl_indications(iso_file, dest_file);
        destroy_dummy_iso_file(dest_file);
    }

    destroy_dummy_iso_file(iso_file);

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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    