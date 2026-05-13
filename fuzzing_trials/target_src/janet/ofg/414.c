#include <stdint.h>
#include <stdlib.h>
#include "janet.h"  // Assuming this is the header file where JanetParser is defined

int LLVMFuzzerTestOneInput_414(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Allocate and initialize a JanetParser
    JanetParser parser;
    janet_parser_init(&parser);

    // Simulate feeding data to the parser
    for (size_t i = 0; i < size; i++) {
        janet_parser_consume(&parser, data[i]);
    }

    // Call the function-under-test
    janet_parser_eof(&parser);

    // Clean up the parser
    janet_parser_deinit(&parser);

    // Deinitialize the Janet environment
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

    LLVMFuzzerTestOneInput_414(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
