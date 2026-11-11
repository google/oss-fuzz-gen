#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libyang/src/tree_data.h"
#include "/src/libyang/src/in.h"

int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct ly_in *input = NULL;
    struct lyd_node *node = NULL;
    LY_ERR err;
    const char *module_name = "example-module";
    LYD_FORMAT format = LYD_XML;
    uint32_t options1 = 0;
    uint32_t options2 = 0;
    uint32_t options3 = 0;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS || ctx == NULL) {
        fprintf(stderr, "Failed to create libyang context\n");
        return 0;
    }

    // Create a new input handler
    ly_in_new_memory((const char *)data, &input);
    if (input == NULL) {
        fprintf(stderr, "Failed to create input handler\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    err = lyd_parse_value_fragment(ctx, module_name, input, format, options1, options2, options3, &node);

    // Clean up
    lyd_free_all(node);
    ly_in_free(input, 0);
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

    LLVMFuzzerTestOneInput_128(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
