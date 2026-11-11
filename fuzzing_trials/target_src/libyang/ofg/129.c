#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node1 = NULL, *node2 = NULL, *siblings = NULL;
    LY_ERR err;
    static bool log = false;

    if (!log) {
        ly_log_options(0);
        log = true;
    }

    // Create a new libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        exit(EXIT_FAILURE);
    }

    // Define a simple schema
    const char *schema = "module test {namespace urn:test;prefix t;yang-version 1.1;"
                         "leaf leaf1 {type string;}"
                         "leaf leaf2 {type string;}}";

    // Parse the schema
    lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);

    // Create a dummy data tree based on the schema
    node1 = lyd_new_path(NULL, ctx, "/test:leaf1", "value1", 0, 0);
    node2 = lyd_new_path(NULL, ctx, "/test:leaf2", "value2", 0, 0);

    // Fuzzing the function-under-test
    err = lyd_insert_sibling(node1, node2, &siblings);
    
    // Clean up
    lyd_free_all(siblings);
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

    LLVMFuzzerTestOneInput_129(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
