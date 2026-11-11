#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_199(const uint8_t *data, size_t size) {
    // Check if size is sufficient for extracting parameters
    if (size < 2) {
        return 0;
    }

    // Initialize sqlite3_str object
    sqlite3_str *str = sqlite3_str_new(NULL);

    // Extract parameters from the data
    int count = (int)data[0]; // Use the first byte for the count
    char character = (char)data[1]; // Use the second byte for the character

    // Call the function-under-test
    sqlite3_str_appendchar(str, count, character);

    // Clean up
    sqlite3_str_finish(str);

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

    LLVMFuzzerTestOneInput_199(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
