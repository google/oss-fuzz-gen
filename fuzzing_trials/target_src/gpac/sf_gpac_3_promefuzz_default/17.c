// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_set_timescale at isom_write.c:451:8 in isomedia.h
// gf_isom_update_edit_list_duration at isom_write.c:8473:8 in isomedia.h
// gf_isom_set_alternate_group_id at isom_write.c:6981:8 in isomedia.h
// gf_isom_set_root_od_id at isom_write.c:601:8 in isomedia.h
// gf_isom_clone_pl_indications at isom_write.c:4010:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

#define DUMMY_FILE_PATH "./dummy_file"
#define TMP_DIR_PATH "/tmp"

static GF_ISOFile* create_dummy_isofile() {
    FILE *dummy_file = fopen(DUMMY_FILE_PATH, "wb");
    if (!dummy_file) return NULL;
    fclose(dummy_file);

    GF_ISOFile *file = gf_isom_open(DUMMY_FILE_PATH, GF_ISOM_OPEN_WRITE, TMP_DIR_PATH);
    return file;
}

static void cleanup_isofile(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return 0;

    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    u32 timeScale = *((u32 *)Data);
    u32 trackNumber = (Size > sizeof(u32)) ? *((u32 *)(Data + sizeof(u32))) : 1;
    u32 groupId = (Size > 2 * sizeof(u32)) ? *((u32 *)(Data + 2 * sizeof(u32))) : 1;
    u32 OD_ID = (Size > 3 * sizeof(u32)) ? *((u32 *)(Data + 3 * sizeof(u32))) : 1;

    // Fuzz gf_isom_set_timescale
    GF_Err err = gf_isom_set_timescale(isom_file, timeScale);
    if (err != GF_OK) {
        cleanup_isofile(isom_file);
        return 0;
    }

    // Fuzz gf_isom_update_edit_list_duration
    err = gf_isom_update_edit_list_duration(isom_file, trackNumber);
    if (err != GF_OK) {
        cleanup_isofile(isom_file);
        return 0;
    }

    // Fuzz gf_isom_set_alternate_group_id
    err = gf_isom_set_alternate_group_id(isom_file, trackNumber, groupId);
    if (err != GF_OK) {
        cleanup_isofile(isom_file);
        return 0;
    }

    // Fuzz gf_isom_set_root_od_id
    err = gf_isom_set_root_od_id(isom_file, OD_ID);
    if (err != GF_OK) {
        cleanup_isofile(isom_file);
        return 0;
    }

    // Create another dummy ISO file for clone operation
    GF_ISOFile *dest_file = create_dummy_isofile();
    if (!dest_file) {
        cleanup_isofile(isom_file);
        return 0;
    }

    // Fuzz gf_isom_clone_pl_indications
    err = gf_isom_clone_pl_indications(isom_file, dest_file);
    if (err != GF_OK) {
        cleanup_isofile(isom_file);
        cleanup_isofile(dest_file);
        return 0;
    }

    // Fuzz gf_isom_close
    err = gf_isom_close(isom_file);
    if (err != GF_OK) {
        cleanup_isofile(isom_file);
        cleanup_isofile(dest_file);
        return 0;
    }

    err = gf_isom_close(dest_file);
    if (err != GF_OK) {
        cleanup_isofile(dest_file);
        return 0;
    }

    cleanup_isofile(isom_file);
    cleanup_isofile(dest_file);
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

        LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    