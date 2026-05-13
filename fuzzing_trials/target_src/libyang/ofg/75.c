#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lys_module *module = NULL;
    LY_ERR err;
    int fd;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a temporary file
    fd = mkstemp(tmpl);
    if (fd == -1) {
        fprintf(stderr, "Failed to create temporary file\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        fprintf(stderr, "Failed to write data to temporary file\n");
        close(fd);
        unlink(tmpl);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Reset the file descriptor's position to the beginning
    lseek(fd, 0, SEEK_SET);

    // Call the function-under-test
    lys_parse_fd(ctx, fd, LYS_IN_YANG, &module);

    // Clean up
    close(fd);
    unlink(tmpl);
    ly_ctx_destroy(ctx);

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

    LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
