#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_141(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd;
    bool result;

    // Ensure that the size is non-zero to create a valid file
    if (size == 0) {
        return 0;
    }

    // Create a temporary file from the fuzz data
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }

    // Close the file descriptor as it is not needed anymore
    close(fd);

    // Initialize the UCL parser
    parser = ucl_parser_new(UCL_PARSER_DEFAULT);
    if (parser == NULL) {
        return 0;
    }

    // Call the function-under-test with the temporary file
    result = ucl_parser_set_filevars(parser, tmpl, true);

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

    LLVMFuzzerTestOneInput_141(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
