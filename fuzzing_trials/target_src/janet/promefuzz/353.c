// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_parser_deinit at parse.c:804:6 in janet.h
// janet_parser_consume at parse.c:697:6 in janet.h
// janet_parser_eof at parse.c:717:6 in janet.h
// janet_parser_error at parse.c:744:13 in janet.h
// janet_parser_flush at parse.c:737:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_parser_init at parse.c:784:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void initialize_parser(JanetParser *parser) {
    janet_parser_init(parser);
}

static void deinitialize_parser(JanetParser *parser) {
    janet_parser_deinit(parser);
}

static void consume_data(JanetParser *parser, const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        janet_parser_consume(parser, data[i]);
    }
}

static void handle_eof(JanetParser *parser) {
    janet_parser_eof(parser);
}

static void handle_error(JanetParser *parser) {
    const char *error = janet_parser_error(parser);
    if (error) {
        fprintf(stderr, "Parser error: %s\n", error);
    }
}

static void flush_parser(JanetParser *parser) {
    janet_parser_flush(parser);
}

int LLVMFuzzerTestOneInput_353(const uint8_t *Data, size_t Size) {
    // Initialize Janet VM before using any parser functions
    if (!janet_init()) {
        return 0; // If initialization fails, exit early
    }

    JanetParser parser;

    // Initialize the parser
    initialize_parser(&parser);

    // Consume the input data
    consume_data(&parser, Data, Size);

    // Simulate end of file
    handle_eof(&parser);

    // Check for errors and handle them
    handle_error(&parser);

    // Flush the parser to reset its state
    flush_parser(&parser);

    // Deinitialize the parser
    deinitialize_parser(&parser);

    // Cleanup Janet VM
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_353(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    