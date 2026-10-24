// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_parser_consume at parse.c:697:6 in janet.h
// janet_parser_flush at parse.c:737:6 in janet.h
// janet_parser_eof at parse.c:717:6 in janet.h
// janet_parser_flush at parse.c:737:6 in janet.h
// janet_parser_has_more at parse.c:855:5 in janet.h
// janet_parser_flush at parse.c:737:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_parser_init at parse.c:784:6 in janet.h
// janet_parser_deinit at parse.c:804:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void fuzz_janet_parser(JanetParser *parser, const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        janet_parser_consume(parser, data[i]);
        if (parser->error) {
            janet_parser_flush(parser);
            return;
        }
    }
    janet_parser_eof(parser);
    if (parser->error) {
        janet_parser_flush(parser);
    } else if (janet_parser_has_more(parser)) {
        janet_parser_flush(parser);
    }
}

int LLVMFuzzerTestOneInput_537(const uint8_t *Data, size_t Size) {
    // Initialize Janet VM
    janet_init();

    JanetParser parser;
    memset(&parser, 0, sizeof(JanetParser));
    janet_parser_init(&parser);

    fuzz_janet_parser(&parser, Data, Size);

    janet_parser_deinit(&parser);

    // Deinitialize Janet VM
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

        LLVMFuzzerTestOneInput_537(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    