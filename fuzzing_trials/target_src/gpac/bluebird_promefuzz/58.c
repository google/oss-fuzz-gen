#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* initialize_iso_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);
    
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = initialize_iso_file(Data, Size);
    if (!isom_file) return 0;

    u32 brand = 0, minorVersion = 0, AlternateBrandsCount = 0;
    gf_isom_get_brand_info(isom_file, &brand, &minorVersion, &AlternateBrandsCount);

    u32 next_group_id = gf_isom_get_next_alternate_group_id(isom_file);

    const u32 *brands = gf_isom_get_brands(isom_file);

    u32 chapter_count_movie = gf_isom_get_chapter_count(isom_file, 0);
    u32 chapter_count_track = gf_isom_get_chapter_count(isom_file, 1);

    u32 copyright_count = gf_isom_get_copyright_count(isom_file);

    u32 switchGroupID = 0, criteriaListSize = 0;
    const u32 *criteria = gf_isom_get_track_switch_parameter(isom_file, 1, 1, &switchGroupID, &criteriaListSize);

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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
