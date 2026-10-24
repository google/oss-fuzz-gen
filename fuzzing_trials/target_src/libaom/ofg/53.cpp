#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Assuming the function is defined in an external C library
extern "C" {
    const char * aom_codec_version_str();
}

extern "C" int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    // Call the function-under-test
    const char *version_str = aom_codec_version_str();

    // Print the version string to ensure it's being called and used
    if (version_str != NULL) {
        printf("AOM Codec Version: %s\n", version_str);
    }

    // The function does not take any input parameters, so we don't use 'data' or 'size'
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

    LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
