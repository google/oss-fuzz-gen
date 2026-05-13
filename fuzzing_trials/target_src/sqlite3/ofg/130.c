#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>  // Include for malloc and free
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to create two non-empty strings
    if (size < 2) {
        return 0;
    }

    // Divide the input data into two parts for two strings
    size_t mid = size / 2;
    const char *str1 = (const char *)data;
    const char *str2 = (const char *)(data + mid);

    // Ensure both strings are null-terminated
    char *buffer1 = (char *)malloc(mid + 1);
    char *buffer2 = (char *)malloc(size - mid + 1);
    if (buffer1 == NULL || buffer2 == NULL) {
        free(buffer1);
        free(buffer2);
        return 0;
    }

    memcpy(buffer1, str1, mid);
    buffer1[mid] = '\0';

    memcpy(buffer2, str2, size - mid);
    buffer2[size - mid] = '\0';

    // Call the function-under-test
    int result = sqlite3_stricmp(buffer1, buffer2);

    // Clean up
    free(buffer1);
    free(buffer2);

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

    LLVMFuzzerTestOneInput_130(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
