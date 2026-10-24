#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"
#include <string.h> // Include string.h for strlen function

int LLVMFuzzerTestOneInput_310(const uint8_t *data, size_t size) {
    if (size < 4) { // Ensure there is enough data for key, doc, and value
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(10);

    // Use the first byte of data as an index for the string
    size_t str_index = data[0] % size; // Ensure index is within bounds
    const char *key = (const char *)&data[str_index];

    // Ensure the key is null-terminated
    char key_buffer[256];
    size_t key_len = 0;
    while (key_len < 255 && str_index + key_len < size && data[str_index + key_len] != '\0') {
        key_buffer[key_len] = data[str_index + key_len];
        key_len++;
    }
    key_buffer[key_len] = '\0';

    // Use the second byte of data as an index for the documentation string
    size_t doc_index = data[1] % size; // Ensure index is within bounds
    const char *doc = (const char *)&data[doc_index];

    // Ensure the doc is null-terminated
    char doc_buffer[256];
    size_t doc_len = 0;
    while (doc_len < 255 && doc_index + doc_len < size && data[doc_index + doc_len] != '\0') {
        doc_buffer[doc_len] = data[doc_index + doc_len];
        doc_len++;
    }
    doc_buffer[doc_len] = '\0';

    // Create a Janet value from the remaining data
    Janet value = janet_wrap_number((double)(data[2] % 256));

    // Call the function-under-test
    janet_def(table, key_buffer, value, doc_buffer);

    // Clean up the Janet environment
    janet_deinit();

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

    LLVMFuzzerTestOneInput_310(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
