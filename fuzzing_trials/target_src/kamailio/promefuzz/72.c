// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// eat_line at parser_f.c:37:7 in parser_f.h
// eat_space_end at parser_f.h:43:21 in parser_f.h
// is_empty_end at parser_f.h:85:19 in parser_f.h
// eat_lws_end at parser_f.h:50:21 in parser_f.h
// ksr_buf_oneline at msg_parser.c:1152:7 in msg_parser.h
// eat_token_end at parser_f.h:67:21 in parser_f.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "parser_f.h"
#include "msg_parser.h"

#define DUMMY_FILE "./dummy_file"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_72(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Prepare a buffer and ensure it's null-terminated
    char *buffer = (char *)malloc(Size + 1);
    if (!buffer) return 0;
    memcpy(buffer, Data, Size);
    buffer[Size] = '\0';

    // Fuzz eat_line
    char *result_eat_line = eat_line(buffer, (unsigned int)Size);

    // Fuzz eat_space_end
    char *result_eat_space_end = eat_space_end(buffer, buffer + Size);

    // Fuzz is_empty_end
    int result_is_empty_end = is_empty_end(buffer, buffer + Size);

    // Fuzz eat_lws_end
    char *result_eat_lws_end = eat_lws_end(buffer, buffer + Size);

    // Fuzz ksr_buf_oneline
    char *result_ksr_buf_oneline = ksr_buf_oneline(buffer, (int)Size);

    // Fuzz eat_token_end
    char *result_eat_token_end = eat_token_end(buffer, buffer + Size);

    // Write data to dummy file if needed by any function
    write_dummy_file(Data, Size);

    // Clean up
    free(buffer);

    return 0;
}