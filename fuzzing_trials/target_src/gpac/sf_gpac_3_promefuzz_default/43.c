// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_release_segment at isom_read.c:3459:8 in isomedia.h
// gf_isom_add_desc_to_root_od at isom_write.c:413:8 in isomedia.h
// gf_isom_set_qt_key at isom_write.c:6772:8 in isomedia.h
// gf_isom_remove_edits at isom_write.c:2916:8 in isomedia.h
// gf_isom_switch_source at isom_read.c:6717:8 in isomedia.h
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

int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare a file if needed
    write_dummy_file(Data, Size);

    // Prepare the environment
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    // Initialize a dummy descriptor
    GF_Descriptor *theDesc = (GF_Descriptor *)malloc(sizeof(GF_Descriptor));
    if (!theDesc) {
        gf_isom_close(isom_file);
        return 0;
    }
    memset(theDesc, 0, sizeof(GF_Descriptor));

    // Initialize a dummy QT key
    GF_QT_UDTAKey *key = (GF_QT_UDTAKey *)malloc(sizeof(GF_QT_UDTAKey));
    if (!key) {
        gf_isom_close(isom_file);
        free(theDesc);
        return 0;
    }
    memset(key, 0, sizeof(GF_QT_UDTAKey));

    // Fuzz gf_isom_release_segment
    Bool reset_tables = Data[0] % 2;
    gf_isom_release_segment(isom_file, reset_tables);

    // Fuzz gf_isom_add_desc_to_root_od
    gf_isom_add_desc_to_root_od(isom_file, theDesc);

    // Fuzz gf_isom_set_qt_key
    gf_isom_set_qt_key(isom_file, key);

    // Fuzz gf_isom_remove_edits
    u32 trackNumber = (Size > 4) ? *(u32 *)(Data + 1) : 0;
    gf_isom_remove_edits(isom_file, trackNumber);

    // Fuzz gf_isom_switch_source
    char *url = (char *)malloc(Size + 1);
    if (url) {
        memcpy(url, Data, Size);
        url[Size] = '\0';
        gf_isom_switch_source(isom_file, url);
        free(url);
    }

    // Cleanup
    gf_isom_close(isom_file);
    free(theDesc);
    free(key);

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

        LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    