#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sndfile.h>

extern "C" {
    int sf_format_check(const SF_INFO *);
}

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for an SF_INFO structure
    if (size < sizeof(SF_INFO)) {
        return 0;
    }

    // Initialize SF_INFO structure
    SF_INFO sfinfo;
    std::memset(&sfinfo, 0, sizeof(SF_INFO));

    // Copy data into the SF_INFO structure
    std::memcpy(&sfinfo, data, sizeof(SF_INFO));

    // Call the function-under-test
    int result = sf_format_check(&sfinfo);

    // Optionally print the result for debugging purposes
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
