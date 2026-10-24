#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming the definition of bstr is something like this:
typedef struct {
    char *data;
    size_t len;
} bstr;

// Function signature to be fuzzed
int bstr_begins_with_nocase(const bstr *str1, const bstr *str2);

int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
    // Ensure there's enough data to create two bstr objects
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts for two bstr strings
    size_t mid = size / 2;

    // Create bstr objects
    bstr str1;
    bstr str2;

    // Initialize str1
    str1.data = (char *)malloc(mid + 1);
    if (str1.data == NULL) {
        return 0;
    }
    memcpy(str1.data, data, mid);
    str1.data[mid] = '\0'; // Null-terminate
    str1.len = mid;

    // Initialize str2
    str2.data = (char *)malloc(size - mid + 1);
    if (str2.data == NULL) {
        free(str1.data);
        return 0;
    }
    memcpy(str2.data, data + mid, size - mid);
    str2.data[size - mid] = '\0'; // Null-terminate
    str2.len = size - mid;

    // Call the function-under-test
    int result = bstr_begins_with_nocase(&str1, &str2);

    // Free allocated memory
    free(str1.data);
    free(str2.data);

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

    LLVMFuzzerTestOneInput_144(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
