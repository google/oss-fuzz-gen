#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming bstr is a structure defined as follows:
typedef struct {
    char *data;
    size_t len;
} bstr;

// Function-under-test
int bstr_cmp_nocase(const bstr *b1, const bstr *b2);

// Fuzzing harness
int LLVMFuzzerTestOneInput_103(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to create two bstr objects
    }

    // Split the input data into two parts for two bstr objects
    size_t mid = size / 2;

    // Initialize the first bstr object
    bstr b1;
    b1.data = (char *)malloc(mid + 1);
    if (b1.data == NULL) {
        return 0;
    }
    memcpy(b1.data, data, mid);
    b1.data[mid] = '\0'; // Null-terminate the string
    b1.len = mid;

    // Initialize the second bstr object
    bstr b2;
    b2.data = (char *)malloc(size - mid + 1);
    if (b2.data == NULL) {
        free(b1.data);
        return 0;
    }
    memcpy(b2.data, data + mid, size - mid);
    b2.data[size - mid] = '\0'; // Null-terminate the string
    b2.len = size - mid;

    // Call the function-under-test
    int result = bstr_cmp_nocase(&b1, &b2);

    // Clean up
    free(b1.data);
    free(b2.data);

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

    LLVMFuzzerTestOneInput_103(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
