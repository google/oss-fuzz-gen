#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>
#include <unistd.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_100(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    int fd;
    unsigned int priority;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";

    // Initialize the parser
    parser = ucl_parser_new(0);

    // Create a temporary file and write the fuzz data to it
    fd = mkstemp(tmpl);
    if (fd == -1) {
        ucl_parser_free(parser);
        return 0;
    }

    write(fd, data, size);
    lseek(fd, 0, SEEK_SET);

    // Set a non-zero priority
    priority = 1;

    // Call the function under test
    ucl_parser_add_fd_priority(parser, fd, priority);

    // Clean up
    close(fd);
    unlink(tmpl);
    ucl_parser_free(parser);

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

    LLVMFuzzerTestOneInput_100(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
