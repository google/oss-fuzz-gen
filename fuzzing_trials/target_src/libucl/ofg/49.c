#include <stdint.h>
#include <stddef.h>
#include <ucl.h>
#include <string.h>

int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for testing
    if (size < 2) {
        return 0;
    }

    // Initialize UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Parse the input data as UCL
    ucl_parser_add_chunk(parser, data, size);
    const ucl_object_t *root = ucl_parser_get_object(parser);

    // Ensure we have a valid UCL object
    if (root != NULL) {
        // Use part of the input data as a key for lookup
        size_t key_len = size / 2; // Use half of the input size for key
        char key[key_len + 1];
        memcpy(key, data, key_len);
        key[key_len] = '\0'; // Null-terminate the key

        // Call the function-under-test
        const ucl_object_t *result = ucl_object_lookup(root, key);

        // Optionally, perform additional operations on result
        // (not required for the fuzzing harness)
    }

    // Clean up
    ucl_object_unref(root);
    ucl_parser_free(parser);

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

    LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
