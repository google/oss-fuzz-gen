#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libyang/src/validation.h"
#include "/src/libyang/src/tree.h"
#include "/src/libyang/src/context.h"

int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    struct lyd_node *node = NULL;
    struct lyd_node *result = NULL;
    const struct lysc_ext_instance *ext = NULL;
    uint32_t options = 0;
    LY_ERR err;

    // Initialize the libyang context
    struct ly_ctx *ctx = NULL;
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a dummy schema for testing
    const char *schema = "module test {namespace urn:test;prefix t;container c {leaf l {type string;}}}";
    lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);

    // Parse the data into a lyd_node structure
    char *data_mem = malloc(size + 1);
    if (data_mem == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_mem, data, size);
    data_mem[size] = '\0';

    lyd_parse_data_mem(ctx, data_mem, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &node);
    free(data_mem);

    // Call the function-under-test
    err = lyd_validate_ext(&node, ext, options, &result);

    // Clean up
    lyd_free_all(node);
    lyd_free_all(result);
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

    LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
