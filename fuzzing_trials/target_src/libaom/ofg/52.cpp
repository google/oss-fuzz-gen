#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

extern "C" {
    // Include the necessary header for the function-under-test
    #include <aom/aom_codec.h>
}

// Fuzzing harness for the function-under-test
extern "C" int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    // Call the function-under-test
    const char *version_str = aom_codec_version_str();

    // Print the version string to ensure the function is called
    if (version_str != NULL) {
        printf("AOM Codec Version: %s\n", version_str);
    }

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

    LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
