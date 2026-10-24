#include <string.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL;
    LY_ERR err;
    int fd;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";

    // Create a temporary file and write the fuzz data to it
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Reset the file offset to the beginning
    lseek(fd, 0, SEEK_SET);

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of lyd_parse_data_fd
    lyd_parse_data_fd(ctx, size, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &tree);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    // Clean up
    lyd_free_all(tree);
    ly_ctx_destroy(ctx);

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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
