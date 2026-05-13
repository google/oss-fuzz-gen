#include <ucl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    int fd;
    unsigned int priority = 0; // Example priority value
    enum ucl_duplicate_strategy duplicate_strategy = UCL_DUPLICATE_APPEND; // Example strategy
    enum ucl_parse_type parse_type = UCL_PARSE_UCL; // Example parse type

    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Reset the file offset to the beginning
    lseek(fd, 0, SEEK_SET);

    // Initialize the UCL parser
    parser = ucl_parser_new(0);
    if (parser == NULL) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    ucl_parser_add_fd_full(parser, fd, priority, duplicate_strategy, parse_type);

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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
