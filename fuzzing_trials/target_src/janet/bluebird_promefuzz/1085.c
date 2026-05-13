#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static void fuzz_janet_parser(JanetParser *parser) {
    // Initialize the parser
    janet_parser_init(parser);

    // Fuzz various parser operations
    if (parser->pending > 0) {
        Janet value = janet_parser_produce(parser);
        (void)value; // Use the produced value
    }

    // Signal end of file
    janet_parser_eof(parser);

    // Flush the parser to reset state
    janet_parser_flush(parser);

    // Produce wrapped value if possible
    if (parser->pending > 0) {
        Janet wrapped_value = janet_parser_produce_wrapped(parser);
        (void)wrapped_value; // Use the wrapped value
    }

    // Clean up parser resources
    janet_parser_deinit(parser);
}

int LLVMFuzzerTestOneInput_1085(const uint8_t *Data, size_t Size) {
    JanetParser parser;

    // Use the input data to manipulate JanetParser fields
    if (Size >= sizeof(JanetParser)) {
        // Copy input data to parser structure
        memcpy(&parser, Data, sizeof(JanetParser));
    } else {
        // Initialize parser with default values if input is too small
        janet_parser_init(&parser);
    }

    // Fuzz the parser with the current configuration
    fuzz_janet_parser(&parser);

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

    LLVMFuzzerTestOneInput_1085(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
