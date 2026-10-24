#include <sys/stat.h>
#include <string.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>

extern "C" {
    char * lou_findTable(const char *);
}

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Ensure the input is null-terminated
    char *input = (char *)malloc(size + 1);
    if (input == NULL) {
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    char *result = lou_findTable(input);

    // Free the result if it's not NULL
    if (result != NULL) {
        free(result);
    }

    // Free the input
    free(input);

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
