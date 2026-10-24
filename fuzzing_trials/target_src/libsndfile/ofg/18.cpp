#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <sndfile.h>

extern "C" {
    // Include the function-under-test
    int sf_format_check(const SF_INFO *);
}

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Initialize SF_INFO structure
    SF_INFO sfinfo;
    
    // Ensure that the data size is large enough to fill SF_INFO fields
    if (size < sizeof(SF_INFO)) {
        return 0;
    }

    // Copy data into sfinfo fields
    // Note: This assumes that the data is structured appropriately for SF_INFO
    sfinfo.frames = *(sf_count_t *)(data);
    sfinfo.samplerate = *(int *)(data + sizeof(sf_count_t));
    sfinfo.channels = *(int *)(data + sizeof(sf_count_t) + sizeof(int));
    sfinfo.format = *(int *)(data + sizeof(sf_count_t) + 2 * sizeof(int));
    sfinfo.sections = *(int *)(data + sizeof(sf_count_t) + 3 * sizeof(int));
    sfinfo.seekable = *(int *)(data + sizeof(sf_count_t) + 4 * sizeof(int));

    // Call the function-under-test
    int result = sf_format_check(&sfinfo);

    // Optionally, handle the result for debugging purposes
    // printf("sf_format_check result: %d\n", result);

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
