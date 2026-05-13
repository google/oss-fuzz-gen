// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_parser_consume at parse.c:697:6 in janet.h
// janet_parser_eof at parse.c:717:6 in janet.h
// janet_parser_has_more at parse.c:855:5 in janet.h
// janet_parser_flush at parse.c:737:6 in janet.h
// janet_parser_deinit at parse.c:804:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_parser_init at parse.c:784:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <janet.h>

static void fuzz_janet_parser(JanetParser *parser, const uint8_t *data, size_t size) {
    // Initialize the parser
    janet_parser_init(parser);

    // Consume the input data
    for (size_t i = 0; i < size; i++) {
        janet_parser_consume(parser, data[i]);
    }

    // Signal end of input
    janet_parser_eof(parser);

    // Check if parser has more values
    if (janet_parser_has_more(parser)) {
        // If there are more values, flush the parser
        janet_parser_flush(parser);
    }

    // Deinitialize the parser
    janet_parser_deinit(parser);
}

int LLVMFuzzerTestOneInput_772(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Initialize Janet VM
    if (!janet_init()) {
        return 0; // Ensure the Janet VM initializes correctly
    }

    JanetParser parser;
    fuzz_janet_parser(&parser, Data, Size);

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

        LLVMFuzzerTestOneInput_772(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    