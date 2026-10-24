#include <sys/stat.h>
#include "stdbool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    struct lyd_node *src_node = NULL;
    char *value = NULL;
    uint32_t options = 0;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a dummy schema for testing
    const char *schema = "module test {namespace urn:test;prefix t;container c {leaf l {type string;}}}";
    err = lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse schema\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Create a dummy data tree
    const char *data_tree = "<c xmlns=\"urn:test\"><l>test</l></c>";
    err = lyd_parse_data_mem(ctx, data_tree, LYD_XML, 0, LYD_VALIDATE_PRESENT, &node);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse data tree\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Allocate memory for value and copy fuzz data into it
    value = malloc(size + 1);
    if (value == NULL) {
        lyd_free_all(node);
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(value, data, size);
    value[size] = '\0';

    // Call the function-under-test
    lyd_any_copy_value(node, src_node, value, options);

    // Clean up
    free(value);
    lyd_free_all(node);
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

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
