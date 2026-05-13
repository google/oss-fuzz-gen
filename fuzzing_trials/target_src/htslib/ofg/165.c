#include <stddef.h>
#include <stdint.h>

// Declare the function-under-test
const char *hts_feature_string();

// Fuzzing harness
int LLVMFuzzerTestOneInput_165(const uint8_t *data, size_t size) {
    // Call the function-under-test
    const char *result = hts_feature_string();

    // Use the result in some way to avoid compiler optimizations stripping it away
    // For example, we can check if the result is not NULL
    if (result != NULL) {
        // Do something with the result, like checking its length
        size_t length = 0;
        while (result[length] != '\0') {
            length++;
        }
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_165(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
