#include <sys/stat.h>
#include <string.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" {
    void lou_indexTables(const char **);
}

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated for safe string operations
    char *nullTerminatedData = new char[size + 1];
    memcpy(nullTerminatedData, data, size);
    nullTerminatedData[size] = '\0';

    // Prepare an array of strings (const char *)
    const char *tables[] = { nullTerminatedData, "default_table", "another_table", nullptr };

    // Call the function under test
    lou_indexTables(tables);

    // Clean up
    delete[] nullTerminatedData;

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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
