#include <string.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include "stdbool.h"
#include "libyang.h"

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    LY_ERR err;
    static bool log = false;
    int compiled_size;

    if (!log) {
        ly_log_options(0);
        log = true;
    }

    // Initialize context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        exit(EXIT_FAILURE);
    }

    // Parse schema from the input data
    char *schema = malloc(size + 1);
    if (schema == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(schema, data, size);
    schema[size] = '\0';

    lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);

    // Call the function-under-test
    compiled_size = ly_ctx_compiled_size(ctx);

    // Clean up
    ly_ctx_destroy(ctx);
    free(schema);

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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
