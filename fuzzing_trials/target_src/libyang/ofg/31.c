#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    const struct lyd_node *node = NULL;
    LY_ERR err;
    char *yldata = NULL;
    int options = 0;  // Assuming default options for fuzzing

    // Allocate memory for yldata and ensure it's null-terminated
    yldata = (char *)malloc(size + 1);
    if (yldata == NULL) {
        return 0;
    }
    memcpy(yldata, data, size);
    yldata[size] = '\0';

    // Call the function-under-test
    err = ly_ctx_new_yldata(yldata, node, options, &ctx);

    // Clean up
    ly_ctx_destroy(ctx);
    free(yldata);

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
