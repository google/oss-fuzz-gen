#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "/src/libyang/src/tree_data.h"
#include "/src/libyang/src/context.h"
#include "/src/libyang/src/set.h"
#include "/src/libyang/src/parser_schema.h"

int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    struct lys_module *module = NULL;
    struct ly_set *set = NULL;
    char *errmsg = NULL;
    long double dbl = 0.0;
    ly_bool bool_val = 0;
    LY_ERR err;
    LY_XPATH_TYPE xptype = LY_XPATH_NODE_SET;
    const struct lyxp_var *vars = NULL;
    void *prefix_data = NULL;
    const char *xpath_expr = "/example-module:container";

    // Initialize the context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Load a module to provide context for the XPath evaluation
    err = lys_parse_mem(ctx, "module example-module {namespace urn:example;prefix ex; container container {leaf leaf {type string;}}}", LYS_IN_YANG, &module);
    if (err != LY_SUCCESS || !module) {
        fprintf(stderr, "Failed to parse module\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Create a data tree for the XPath evaluation
    err = lyd_new_path(NULL, ctx, "/example-module:container/leaf", "value", 0, &node);
    if (err != LY_SUCCESS || !node) {
        fprintf(stderr, "Failed to create data tree\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function under test
    err = lyd_eval_xpath4(node, node, module, xpath_expr, LY_VALUE_JSON, prefix_data, vars, &xptype, &set, &errmsg, &dbl, &bool_val);

    // Clean up
    lyd_free_all(node);
    ly_set_free(set, NULL);
    ly_ctx_destroy(ctx);
    free(errmsg);

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

    LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
