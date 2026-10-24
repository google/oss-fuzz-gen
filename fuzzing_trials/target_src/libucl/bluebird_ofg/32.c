#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "ucl.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd;
    bool result;

    // Create a temporary file
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzzing data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    // Initialize the UCL parser
    parser = ucl_parser_new(0);
    if (parser == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    const char riuuqfuk[1024] = "ywslf";
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of ucl_parser_add_file_priority
    result = ucl_parser_add_file_priority(parser, riuuqfuk, 0);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
