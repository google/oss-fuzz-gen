#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <ucl.h>

// Function-under-test
// Ensure the function signature matches the one declared in the ucl.h
// No need to redefine it here as it's already declared in the included header
// bool ucl_parser_add_fd_full(struct ucl_parser *parser, int fd, unsigned int priority,
//                             enum ucl_duplicate_strategy strategy,
//                             enum ucl_parse_type parse_type);

int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    struct ucl_parser *parser = ucl_parser_new(0);
    int fd;
    unsigned int priority = 0;
    enum ucl_duplicate_strategy strategy;
    enum ucl_parse_type parse_type;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";

    if (size < 1) {
        ucl_parser_free(parser);
        return 0;
    }

    // Create a temporary file and write the fuzz data to it
    fd = mkstemp(tmpl);
    if (fd == -1) {
        ucl_parser_free(parser);
        return 0;
    }
    write(fd, data, size);
    lseek(fd, 0, SEEK_SET);

    // Set the strategy and parse_type based on the data
    strategy = (enum ucl_duplicate_strategy)(data[0] % 3);
    parse_type = (enum ucl_parse_type)(data[0] % 3);

    // Call the function-under-test
    ucl_parser_add_fd_full(parser, fd, priority, strategy, parse_type);

    // Cleanup
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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
