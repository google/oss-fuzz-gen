// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_parser_init at parse.c:784:6 in janet.h
// janet_parser_deinit at parse.c:804:6 in janet.h
// janet_parser_produce at parse.c:756:7 in janet.h
// janet_parser_eof at parse.c:717:6 in janet.h
// janet_parser_produce_wrapped at parse.c:770:7 in janet.h
// janet_parser_flush at parse.c:737:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static void fuzz_janet_parser_init(JanetParser *parser) {
    janet_parser_init(parser);
}

static void fuzz_janet_parser_deinit(JanetParser *parser) {
    janet_parser_deinit(parser);
}

static void fuzz_janet_parser_produce(JanetParser *parser) {
    if (parser->pending > 0) {
        Janet result = janet_parser_produce(parser);
        (void)result;
    }
}

static void fuzz_janet_parser_eof(JanetParser *parser) {
    janet_parser_eof(parser);
}

static void fuzz_janet_parser_produce_wrapped(JanetParser *parser) {
    if (parser->pending > 0) {
        Janet wrapped_result = janet_parser_produce_wrapped(parser);
        (void)wrapped_result;
    }
}

static void fuzz_janet_parser_flush(JanetParser *parser) {
    janet_parser_flush(parser);
}

int LLVMFuzzerTestOneInput_417(const uint8_t *Data, size_t Size) {
    JanetParser parser;
    fuzz_janet_parser_init(&parser);

    // Simulate diverse inputs and states
    if (Size > 0) {
        switch (Data[0] % 6) {
            case 0:
                fuzz_janet_parser_produce(&parser);
                break;
            case 1:
                fuzz_janet_parser_eof(&parser);
                break;
            case 2:
                fuzz_janet_parser_produce_wrapped(&parser);
                break;
            case 3:
                fuzz_janet_parser_flush(&parser);
                break;
            case 4:
                // Simulate other operations
                break;
            case 5:
                // Simulate other operations
                break;
            default:
                break;
        }
    }

    fuzz_janet_parser_deinit(&parser);
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

        LLVMFuzzerTestOneInput_417(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    