#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

// Include the function-under-test
extern "C" {
    char * lou_setDataPath(const char *);
}

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated by creating a new buffer
    char *dataPath = new char[size + 1];
    if (dataPath == nullptr) {
        return 0; // Allocation failed, exit early
    }

    // Copy the input data to the buffer and null-terminate it
    memcpy(dataPath, data, size);
    dataPath[size] = '\0';

    // Call the function-under-test
    char *result = lou_setDataPath(dataPath);

    // Clean up
    delete[] dataPath;

    // Optionally, you can free or handle the result if needed
    // For example, if lou_setDataPath allocates memory, you should free it
    // free(result);

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
