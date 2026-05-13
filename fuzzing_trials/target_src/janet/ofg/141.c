#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>  // Include the necessary library for malloc and free

// Function-under-test declaration
int janet_cstrcmp(const uint8_t *, const char *);

int LLVMFuzzerTestOneInput_141(const uint8_t *data, size_t size) {
    // Ensure that the size is at least 1 to have a valid null-terminated string
    if (size < 1) {
        return 0;
    }

    // Find the position of the first null byte in data, if it exists
    size_t null_pos = 0;
    while (null_pos < size && data[null_pos] != '\0') {
        null_pos++;
    }

    // Ensure that the null_pos is within bounds
    if (null_pos >= size) {
        return 0;
    }

    // Create a null-terminated string from the data
    // Ensure that the data is null-terminated before passing to janet_cstrcmp
    char *cstr = (char *)malloc(null_pos + 1);
    if (cstr == NULL) {
        return 0;
    }
    memcpy(cstr, data, null_pos);
    cstr[null_pos] = '\0';

    // Ensure that the data is also null-terminated
    uint8_t *null_terminated_data = (uint8_t *)malloc(null_pos + 1);
    if (null_terminated_data == NULL) {
        free(cstr);
        return 0;
    }
    memcpy(null_terminated_data, data, null_pos);
    null_terminated_data[null_pos] = '\0';

    // Call the function-under-test
    janet_cstrcmp(null_terminated_data, cstr);

    // Clean up
    free(cstr);
    free(null_terminated_data);
    
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

    LLVMFuzzerTestOneInput_141(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
