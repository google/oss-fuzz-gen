#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile *initialize_iso_file() {
    // Assuming a function or a way to create a GF_ISOFile exists within the library
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return isom_file;
}

static GF_QT_UDTAKey *initialize_qt_udta_key(const uint8_t *data, size_t size) {
    GF_QT_UDTAKey *key = (GF_QT_UDTAKey *)malloc(sizeof(GF_QT_UDTAKey));
    if (!key) return NULL;

    // Ensure the string is null-terminated
    char *name = (char *)malloc(size + 1);
    if (!name) {
        free(key);
        return NULL;
    }
    memcpy(name, data, size);
    name[size] = '\0';

    key->name = name;
    return key;
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

static void cleanup_qt_udta_key(GF_QT_UDTAKey *key) {
    if (key) {
        if (key->name) free(key->name);
        free(key);
    }
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile *isom_file = initialize_iso_file();
    if (!isom_file) return 0;

    // Fuzzing gf_isom_set_qt_key
    GF_QT_UDTAKey *key = initialize_qt_udta_key(Data, Size);
    if (key) {
        gf_isom_set_qt_key(isom_file, key);
        cleanup_qt_udta_key(key);
    }

    // Fuzzing gf_isom_sdp_clean
    gf_isom_sdp_clean(isom_file);

    // Fuzzing gf_isom_enum_udta_keys
    GF_QT_UDTAKey out_key;
    gf_isom_enum_udta_keys(isom_file, Data[0] % 256, &out_key);

    // Fuzzing gf_isom_rewrite_track_dependencies
    gf_isom_rewrite_track_dependencies(isom_file, Data[0] % 256);

    // Fuzzing gf_isom_get_sample_references
    u32 refID, nb_refs;
    const u32 *refs;
    gf_isom_get_sample_references(isom_file, Data[0] % 256, Data[0] % 256, &refID, &nb_refs, &refs);

    // Fuzzing gf_isom_sdp_clean_track
    gf_isom_sdp_clean_track(isom_file, Data[0] % 256);

    cleanup_iso_file(isom_file);

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
