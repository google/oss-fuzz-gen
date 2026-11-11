#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Ensure Janet is initialized before using any Janet functions
static void initialize_janet_353() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

int LLVMFuzzerTestOneInput_353(const uint8_t *data, size_t size) {
    initialize_janet_353();

    // Create a JanetParser object
    JanetParser parser;
    janet_parser_init(&parser);

    // Feed the parser with the input data
    for (size_t i = 0; i < size; i++) {
        janet_parser_consume(&parser, data[i]);
    }

    // Call the function-under-test
    enum JanetParserStatus status = janet_parser_status(&parser);

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

    LLVMFuzzerTestOneInput_353(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
