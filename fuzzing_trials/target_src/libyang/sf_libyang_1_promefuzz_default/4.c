// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lys_parse_mem at tree_schema.c:2872:1 in parser_schema.h
// lyd_new_inner at tree_data_new.c:446:1 in tree_data.h
// ly_ctx_new at context.c:278:1 in context.h
// lyd_new_list2 at tree_data_new.c:581:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_any at tree_data_new.c:749:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_validate_module at validation.c:2217:1 in parser_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_unlink_tree at tree_data.c:1293:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_insert_child at tree_data.c:1095:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "libyang.h"

// Function to create a dummy module
static struct lys_module *create_dummy_module(struct ly_ctx *ctx) {
    const char *module_data = "module dummy {namespace \"urn:dummy\"; prefix d; list mylist { key \"name\"; leaf name { type string; } } }";
    struct lys_module *module;
    if (lys_parse_mem(ctx, module_data, LYS_IN_YANG, &module)) {
        return NULL;
    }
    return module;
}

// Function to create a dummy parent node
static struct lyd_node *create_dummy_parent_node(struct ly_ctx *ctx) {
    struct lys_module *module = create_dummy_module(ctx);
    if (!module) {
        return NULL;
    }
    struct lyd_node *parent;
    if (lyd_new_inner(NULL, module, "mylist", 0, &parent)) {
        return NULL;
    }
    return parent;
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx;
    struct lys_module *module;
    struct lyd_node *parent = NULL, *node = NULL, *child = NULL, *tree = NULL, *diff = NULL;
    LY_ERR ret;

    // Initialize context
    if (ly_ctx_new(NULL, 0, &ctx)) {
        return 0;
    }

    // Create dummy module and parent node
    module = create_dummy_module(ctx);
    parent = create_dummy_parent_node(ctx);

    // Prepare inputs
    const char *name = "mylist";
    const char *keys = "[name='dummy']";
    uint32_t options = 0;

    // Fuzz target: lyd_new_list2
    ret = lyd_new_list2(parent, module, name, keys, options, &node);
    if (ret == LY_SUCCESS && node) {
        lyd_free_tree(node);
        node = NULL;
    }

    // Fuzz target: lyd_new_any
    const char *value = (Size > 0) ? (const char *)Data : NULL;
    if (value && memchr(value, '\0', Size)) {
        ret = lyd_new_any(parent, module, name, child, value, 0, options, &node);
        if (ret == LY_SUCCESS && node) {
            lyd_free_tree(node);
            node = NULL;
        }
    }

    // Fuzz target: lyd_validate_module
    ret = lyd_validate_module(&tree, module, 0, &diff);
    if (ret == LY_SUCCESS && diff) {
        lyd_free_tree(diff);
        diff = NULL;
    }

    // Fuzz target: lyd_unlink_tree
    if (parent) {
        ret = lyd_unlink_tree(parent);
        if (ret == LY_SUCCESS) {
            lyd_free_tree(parent);
            parent = NULL;
        }
    }

    // Fuzz target: lyd_new_term
    if (value && memchr(value, '\0', Size)) {
        ret = lyd_new_term(NULL, module, name, value, options, &node);
        if (ret == LY_SUCCESS && node) {
            lyd_free_tree(node);
            node = NULL;
        }
    }

    // Fuzz target: lyd_insert_child
    if (parent && node) {
        ret = lyd_insert_child(parent, node);
        if (ret == LY_SUCCESS) {
            lyd_free_tree(node);
            node = NULL;
        }
    }

    // Cleanup
    if (parent) {
        lyd_free_tree(parent);
    }
    if (ctx) {
        ly_ctx_destroy(ctx);
    }

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

        LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    