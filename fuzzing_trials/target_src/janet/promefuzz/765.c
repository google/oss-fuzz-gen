// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_parser_produce at parse.c:756:7 in janet.h
// janet_parser_produce_wrapped at parse.c:770:7 in janet.h
// janet_parser_init at parse.c:784:6 in janet.h
// janet_parser_eof at parse.c:717:6 in janet.h
// janet_parser_flush at parse.c:737:6 in janet.h
// janet_parser_deinit at parse.c:804:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static void fuzz_janet_parser_produce(JanetParser *parser) {
    if (parser->pending > 0) {
        Janet result = janet_parser_produce(parser);
        (void)result; // Suppress unused variable warning
    }
}

static void fuzz_janet_parser_produce_wrapped(JanetParser *parser) {
    if (parser->pending > 0) {
        Janet result = janet_parser_produce_wrapped(parser);
        (void)result; // Suppress unused variable warning
    }
}

int LLVMFuzzerTestOneInput_765(const uint8_t *Data, size_t Size) {
    // Initialize a JanetParser
    JanetParser parser;
    janet_parser_init(&parser);

    // Allocate buffer for parser and copy data into it
    parser.buf = (uint8_t *)malloc(Size);
    if (parser.buf) {
        memcpy(parser.buf, Data, Size);
        parser.bufcount = Size;
    }

    // Call various functions to explore different states
    fuzz_janet_parser_produce(&parser);
    fuzz_janet_parser_produce_wrapped(&parser);
    janet_parser_eof(&parser);
    janet_parser_flush(&parser);

    // Cleanup
    if (parser.buf) {
        parser.buf = NULL; // Avoid double-free by nullifying the pointer
    }
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_765(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    