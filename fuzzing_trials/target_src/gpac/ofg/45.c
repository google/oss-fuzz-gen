#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    GF_ISOProfileLevelType PL_Code;
    u8 ProfileLevel;

    // Initialize movie with a non-null value
    movie = gf_isom_open("temp.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) {
        return 0;
    }

    // Ensure size is sufficient to extract PL_Code and ProfileLevel
    if (size < sizeof(GF_ISOProfileLevelType) + sizeof(u8)) {
        gf_isom_close(movie);
        return 0;
    }

    // Extract PL_Code and ProfileLevel from data
    PL_Code = *(GF_ISOProfileLevelType *)data;
    ProfileLevel = *(u8 *)(data + sizeof(GF_ISOProfileLevelType));

    // Call the function-under-test
    gf_isom_set_pl_indication(movie, PL_Code, ProfileLevel);

    // Clean up
    gf_isom_close(movie);

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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
