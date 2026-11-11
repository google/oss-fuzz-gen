#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ucl.h>
#include <fcntl.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Initialize the ucl_parser structure
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Create a temporary file and write the fuzzing data to it
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        ucl_parser_free(parser);
        return 0;
    }

    // Write data to the file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        ucl_parser_free(parser);
        return 0;
    }

    // Reset file offset to the beginning
    lseek(fd, 0, SEEK_SET);

    // Define a non-zero priority
    unsigned int priority = 1;

    // Call the function-under-test
    bool result = ucl_parser_add_fd_priority(parser, fd, priority);

    // Clean up
    close(fd);
    ucl_parser_free(parser);

    // Return 0 to indicate the fuzzer should continue
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

    LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
