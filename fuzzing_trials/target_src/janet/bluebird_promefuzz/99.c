#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void initialize_janet_runtime() {
    janet_init();
}

static void cleanup_janet_runtime() {
    janet_deinit();
}

static void initialize_parser(JanetParser *parser) {
    janet_parser_init(parser);
}

static void cleanup_parser(JanetParser *parser) {
    janet_parser_deinit(parser);
}

static void feed_data_to_parser(JanetParser *parser, const uint8_t *Data, size_t Size) {
    for (size_t i = 0; i < Size; i++) {
        // Ensure parser and its state are valid before consuming
        if (parser->error != NULL) {
            break;
        }
        janet_parser_consume(parser, Data[i]);
    }
}

static void signal_end_of_parsing(JanetParser *parser) {
    if (parser->error == NULL) {
        janet_parser_eof(parser);
    }
}

static void flush_parser(JanetParser *parser) {
    if (parser->error != NULL) {
        janet_parser_flush(parser);
    }
}

static int check_parser_has_more(JanetParser *parser) {
    return janet_parser_has_more(parser);
}

int LLVMFuzzerTestOneInput_99(const uint8_t *Data, size_t Size) {
    // Check if the input size is sufficient to avoid parsing errors
    if (Size == 0) {
        return 0;
    }

    initialize_janet_runtime();

    JanetParser parser;
    initialize_parser(&parser);

    feed_data_to_parser(&parser, Data, Size);

    if (parser.error == NULL && check_parser_has_more(&parser)) {
        // Simulate consuming more data if parser has more values
        signal_end_of_parsing(&parser);
    }

    flush_parser(&parser);

    cleanup_parser(&parser);
    cleanup_janet_runtime();
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

    LLVMFuzzerTestOneInput_99(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
