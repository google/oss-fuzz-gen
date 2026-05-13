#include <cstdint>
#include <cstddef>
#include <cstring>
#include <iostream>

extern "C" {
    int lou_compileString(const char *, const char *);
}

extern "C" int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create two non-empty strings
    if (size < 2) {
        return 0;
    }

    // Find a position to split the data into two strings
    size_t split_pos = size / 2;

    // Create the first string
    char *str1 = new char[split_pos + 1];
    std::memcpy(str1, data, split_pos);
    str1[split_pos] = '\0'; // Null-terminate the string

    // Create the second string
    char *str2 = new char[size - split_pos + 1];
    std::memcpy(str2, data + split_pos, size - split_pos);
    str2[size - split_pos] = '\0'; // Null-terminate the string

    // Call the function-under-test
    lou_compileString(str1, str2);

    // Clean up
    delete[] str1;
    delete[] str2;

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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
