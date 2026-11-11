// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_get_module_implemented at context.c:1009:1 in context.h
// lyd_new_inner at tree_data_new.c:446:1 in tree_data.h
// ly_ctx_load_module at context.c:239:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// lyd_dup_siblings at tree_data.c:2535:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_list3 at tree_data_new.c:632:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_eval_xpath3 at tree_data.c:3463:1 in tree_data.h
// lyd_trim_xpath at tree_data.c:3581:1 in tree_data.h
// lyd_validate_module at validation.c:2217:1 in parser_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libyang.h>
#include <parser_data.h>
#include <tree_data.h>

static struct lyd_node* create_sample_data_node(struct ly_ctx *ctx) {
    struct lyd_node *node = NULL;
    const struct lys_module *module = ly_ctx_get_module_implemented(ctx, "sample-module");
    lyd_new_inner(NULL, module, "sample-node", 0, &node);
    return node;
}

static const struct lys_module* create_sample_module(struct ly_ctx *ctx) {
    const char *features[] = {NULL};
    return ly_ctx_load_module(ctx, "sample-module", NULL, features);
}

int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL, *dup = NULL, *parent = NULL;
    const struct lys_module *module = NULL;
    const char *name = "sample-list";
    const void *key_values[1] = { "key1" };
    uint32_t value_sizes_bits[1] = { 8 };
    uint32_t options = 0;
    ly_bool result;
    LY_ERR err;

    // Initialize context
    if (ly_ctx_new(NULL, LY_CTX_DISABLE_SEARCHDIRS, &ctx)) {
        return 0;
    }

    // Create a sample module and node
    module = create_sample_module(ctx);
    node = create_sample_data_node(ctx);

    // Fuzzing lyd_dup_siblings
    err = lyd_dup_siblings(node, parent, options, &dup);
    if (err != LY_SUCCESS) {
        lyd_free_tree(dup);
    }

    // Fuzzing lyd_new_list3
    err = lyd_new_list3(parent, module, name, key_values, value_sizes_bits, options, &node);
    if (err != LY_SUCCESS) {
        lyd_free_tree(node);
    }

    // Fuzzing lyd_eval_xpath3
    err = lyd_eval_xpath3(node, module, "/sample-module:sample-node", 0, NULL, NULL, &result);
    if (err != LY_SUCCESS) {
        // Handle error if needed
    }

    // Fuzzing lyd_trim_xpath
    err = lyd_trim_xpath(&node, "/sample-module:sample-node", NULL);
    if (err != LY_SUCCESS) {
        // Handle error if needed
    }

    // Fuzzing lyd_validate_module
    err = lyd_validate_module(&node, module, options, NULL);
    if (err != LY_SUCCESS) {
        // Handle error if needed
    }

    // Fuzzing lyd_new_term
    char *value = (char *)malloc(Size + 1);
    if (value) {
        memcpy(value, Data, Size);
        value[Size] = '\0';
        err = lyd_new_term(parent, module, "sample-leaf", value, options, &node);
        free(value);
        if (err != LY_SUCCESS) {
            lyd_free_tree(node);
        }
    }

    // Cleanup
    lyd_free_tree(node);
    lyd_free_tree(dup);
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

        LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    