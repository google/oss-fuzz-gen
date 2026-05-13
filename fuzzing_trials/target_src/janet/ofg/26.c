#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Initialize Janet runtime
__attribute__((constructor))
void init_janet_runtime() {
    janet_init();
}

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to perform meaningful operations
    if (size < 1) {
        return 0;
    }

    // Initialize a JanetParser
    JanetParser parser;
    janet_parser_init(&parser);

    // Feed each byte of data into the parser
    for (size_t i = 0; i < size; i++) {
        janet_parser_consume(&parser, data[i]);
    }

    // Call the function-under-test
    Janet result = janet_parser_produce_wrapped(&parser);

    // Clean up the parser
    janet_parser_deinit(&parser);

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_26(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
