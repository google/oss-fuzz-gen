#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  // Include for close() and unlink()
#include <fcntl.h>   // Include for mkstemp()
#include <sys/types.h> // Include for ssize_t
#include <ucl.h>

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd;
    unsigned int priority = 0;

    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Initialize UCL parser
    parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Create a temporary file and write data to it
    fd = mkstemp(tmpl);
    if (fd == -1) {
        ucl_parser_free(parser);
        return 0;
    }

    // Write the fuzzing data to the file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        ucl_parser_free(parser);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Fuzz the function with the temporary file
    ucl_parser_add_file_priority(parser, tmpl, priority);

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

    LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
