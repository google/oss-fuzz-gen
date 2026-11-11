#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libyang.h>  // Corrected include statement

int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    struct lyd_meta *meta = NULL;
    ly_bool result;

    // Initialize libyang context
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a dummy schema for testing
    const char *schema = "module test {namespace urn:test;prefix t;leaf test-leaf {type string;}}";
    if (lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL) != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse schema\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Create a dummy data node
    const char *data_str = "<test-leaf xmlns=\"urn:test\">test</test-leaf>";
    if (lyd_parse_data_mem(ctx, data_str, LYD_XML, LYD_PARSE_ONLY, LYD_VALIDATE_PRESENT, &node) != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse data\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Create a dummy metadata
    const struct lys_module *module = ly_ctx_get_module_implemented(ctx, "test");
    if (!module) {
        fprintf(stderr, "Failed to get module\n");
        lyd_free_all(node);
        ly_ctx_destroy(ctx);
        return 0;
    }
    if (lyd_new_meta(ctx, node, module, "dummy-meta", "dummy-value", 0, &meta) != LY_SUCCESS) {
        fprintf(stderr, "Failed to create metadata\n");
        lyd_free_all(node);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    result = lyd_meta_is_internal(meta);

    // Clean up
    lyd_free_meta_single(meta);
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

    LLVMFuzzerTestOneInput_135(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
