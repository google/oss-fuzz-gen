#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <janet.h>

// Initialize the Janet environment
static void initialize_janet_296() {
    janet_init();
}

int LLVMFuzzerTestOneInput_296(const uint8_t *data, size_t size) {
    // Initialize Janet if it's not already initialized
    static bool initialized = false;
    if (!initialized) {
        initialize_janet_296();
        initialized = true;
    }

    // Create a JanetParser
    JanetParser parser;
    janet_parser_init(&parser);

    // Feed the data into the parser one byte at a time
    for (size_t i = 0; i < size; i++) {
        janet_parser_consume(&parser, data[i]);
    }

    // Call the function-under-test
    Janet result = janet_parser_produce(&parser);

    // Clean up the parser
    janet_parser_deinit(&parser);

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

    LLVMFuzzerTestOneInput_296(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
