#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return isom_file;
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = create_dummy_iso_file();
    if (!isom_file) return 0;

    // Fuzz gf_isom_apple_set_tag_ex
    if (Size >= sizeof(GF_ISOiTunesTag)) {
        GF_ISOiTunesTag for_tag;
        memcpy(&for_tag, Data, sizeof(GF_ISOiTunesTag));
        const u8 *data = Data + sizeof(GF_ISOiTunesTag);
        u32 data_len = (Size > sizeof(GF_ISOiTunesTag)) ? (Size - sizeof(GF_ISOiTunesTag)) : 0;
        u64 int_val = 0;
        u32 int_val2 = 0;
        const char *name = NULL;
        const char *mean = NULL;
        u32 locale = 0;
        gf_isom_apple_set_tag_ex(isom_file, for_tag, data, data_len, int_val, int_val2, name, mean, locale);
    }

    // Fuzz gf_isom_apple_enum_tag_ex
    if (Size >= sizeof(u32)) {
        u32 idx;
        memcpy(&idx, Data, sizeof(u32));
        GF_ISOiTunesTag out_tag;
        const u8 *data;
        u32 data_len;
        u64 out_int_val;
        u32 out_int_val2;
        u32 out_flags;
        const char *out_mean;
        const char *out_name;
        u32 out_locale;
        gf_isom_apple_enum_tag_ex(isom_file, idx, &out_tag, &data, &data_len, &out_int_val, &out_int_val2, &out_flags, &out_mean, &out_name, &out_locale);
    }

    // Fuzz gf_isom_guess_specification
    gf_isom_guess_specification(isom_file);

    // Fuzz gf_isom_apple_set_tag
    if (Size >= sizeof(GF_ISOiTunesTag)) {
        GF_ISOiTunesTag tag;
        memcpy(&tag, Data, sizeof(GF_ISOiTunesTag));
        const u8 *data = Data + sizeof(GF_ISOiTunesTag);
        u32 data_len = (Size > sizeof(GF_ISOiTunesTag)) ? (Size - sizeof(GF_ISOiTunesTag)) : 0;
        u64 int_val = 0;
        u32 int_val2 = 0;
        gf_isom_apple_set_tag(isom_file, tag, data, data_len, int_val, int_val2);
    }

    // Fuzz gf_isom_apple_get_tag
    if (Size >= sizeof(GF_ISOiTunesTag)) {
        GF_ISOiTunesTag tag;
        memcpy(&tag, Data, sizeof(GF_ISOiTunesTag));
        const u8 *data;
        u32 data_len;
        gf_isom_apple_get_tag(isom_file, tag, &data, &data_len);
    }

    // Fuzz gf_isom_apple_enum_tag
    if (Size >= sizeof(u32)) {
        u32 idx;
        memcpy(&idx, Data, sizeof(u32));
        GF_ISOiTunesTag out_tag;
        const u8 *data;
        u32 data_len;
        u64 out_int_val;
        u32 out_int_val2;
        u32 out_flags;
        gf_isom_apple_enum_tag(isom_file, idx, &out_tag, &data, &data_len, &out_int_val, &out_int_val2, &out_flags);
    }

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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
