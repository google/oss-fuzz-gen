#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

// Assume the function is defined elsewhere
extern const char * hts_test_feature(unsigned int feature);

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    unsigned int feature;

    if (size < sizeof(unsigned int)) {
        return 0; // Not enough data to form an unsigned int
    }

    // Copy bytes from data to feature, ensuring no overflow
    feature = *(unsigned int *)data;

    // Call the function-under-test
    const char *result = hts_test_feature(feature);

    // Use the result in some way to prevent compiler optimizations from removing the call
    if (result != NULL) {
        // Do something trivial with the result, like checking its length
        while (*result) {
            result++;
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
