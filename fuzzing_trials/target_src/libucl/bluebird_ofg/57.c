#include <sys/stat.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd;
    FILE *file;
    bool result;

    // Create a temporary file
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write data to the temporary file
    file = fdopen(fd, "wb");
    if (file == NULL) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Initialize the parser
    parser = ucl_parser_new(0);

    // Fuzz the function with different enumeration values
    result = ucl_parser_add_file_full(parser, tmpl, 0, UCL_DUPLICATE_APPEND, UCL_PARSE_UCL);
    result = ucl_parser_add_file_full(parser, tmpl, 0, UCL_DUPLICATE_REWRITE, UCL_PARSE_UCL); // Changed UCL_DUPLICATE_REPLACE to UCL_DUPLICATE_REWRITE and UCL_PARSE_JSON to UCL_PARSE_UCL
    result = ucl_parser_add_file_full(parser, tmpl, 0, UCL_DUPLICATE_ERROR, UCL_PARSE_MSGPACK);

    // Clean up
    ucl_parser_free(parser);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
