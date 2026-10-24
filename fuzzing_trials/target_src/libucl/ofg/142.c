#include <stdint.h>
#include <stdbool.h>
#include <ucl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // For mkstemp, write, close, unlink

int LLVMFuzzerTestOneInput_142(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd;
    bool result;
    bool expand = true; // or false, try both

    // Initialize the parser
    parser = ucl_parser_new(UCL_PARSER_DEFAULT);

    // Create a temporary file to write the fuzz data
    fd = mkstemp(tmpl);
    if (fd == -1) {
        ucl_parser_free(parser);
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        ucl_parser_free(parser);
        return 0;
    }
    close(fd);

    // Call the function-under-test
    result = ucl_parser_set_filevars(parser, tmpl, expand);

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

    LLVMFuzzerTestOneInput_142(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
