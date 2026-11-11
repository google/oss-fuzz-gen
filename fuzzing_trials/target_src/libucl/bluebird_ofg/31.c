#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    int fd;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";

    // Create a temporary file
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If file creation fails, exit the fuzzer
    }

    // Write the fuzzing data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0; // If writing fails, clean up and exit
    }

    // Reset file offset to the beginning
    lseek(fd, 0, SEEK_SET);

    // Initialize the UCL parser
    parser = ucl_parser_new(UCL_PARSER_DEFAULT);
    if (parser == NULL) {
        close(fd);
        unlink(tmpl);
        return 0; // If parser creation fails, clean up and exit
    }

    // Call the function-under-test
    ucl_parser_add_fd(parser, fd);

    // Clean up
    ucl_parser_free(parser);
    close(fd);
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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
