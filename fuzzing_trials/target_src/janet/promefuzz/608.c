// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_parser_flush at parse.c:737:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_parser_init at parse.c:784:6 in janet.h
// janet_parser_consume at parse.c:697:6 in janet.h
// janet_parser_status at parse.c:730:24 in janet.h
// janet_parser_status at parse.c:730:24 in janet.h
// janet_parser_eof at parse.c:717:6 in janet.h
// janet_parser_deinit at parse.c:804:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_parser_status at parse.c:730:24 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void handle_parser_status(JanetParser *parser) {
    enum JanetParserStatus status = janet_parser_status(parser);
    switch (status) {
        case JANET_PARSE_ROOT:
            // handle root status
            break;
        case JANET_PARSE_ERROR:
            janet_parser_flush(parser);
            break;
        case JANET_PARSE_PENDING:
            // handle pending status
            break;
        case JANET_PARSE_DEAD:
            // handle dead status
            break;
    }
}

int LLVMFuzzerTestOneInput_608(const uint8_t *Data, size_t Size) {
    // Initialize the Janet runtime environment
    janet_init();

    if (Size == 0) {
        janet_deinit();
        return 0; // Early exit if input size is zero
    }

    JanetParser parser;
    memset(&parser, 0, sizeof(JanetParser)); // Ensure parser is zero-initialized
    janet_parser_init(&parser);

    for (size_t i = 0; i < Size; i++) {
        janet_parser_consume(&parser, Data[i]);
        handle_parser_status(&parser);
        if (janet_parser_status(&parser) == JANET_PARSE_ERROR) {
            break; // Exit loop if parser is in an error state
        }
    }

    // Ensure parser is in a valid state before calling janet_parser_eof
    if (janet_parser_status(&parser) != JANET_PARSE_ERROR) {
        janet_parser_eof(&parser);
        handle_parser_status(&parser);
    }

    janet_parser_deinit(&parser);

    // Deinitialize the Janet runtime environment
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

        LLVMFuzzerTestOneInput_608(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    