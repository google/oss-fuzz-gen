// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_new_list2 at tree_data_new.c:581:1 in tree_data.h
// lyd_new_list3 at tree_data_new.c:632:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_insert_child at tree_data.c:1095:1 in tree_data.h
// lyd_new_list at tree_data_new.c:528:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libyang.h"
#include "tree_data.h"
#include "parser_data.h"

static struct lys_module *create_dummy_module(struct ly_ctx *ctx) {
    struct lys_module *module = malloc(sizeof(struct lys_module));
    if (!module) {
        return NULL;
    }
    memset(module, 0, sizeof(struct lys_module));
    module->ctx = ctx;
    module->name = "dummy-module";
    module->compiled = malloc(sizeof(struct lysc_module));
    if (!module->compiled) {
        free(module);
        return NULL;
    }
    memset(module->compiled, 0, sizeof(struct lysc_module));
    return module;
}

static void free_dummy_module(struct lys_module *module) {
    if (module) {
        free(module->compiled);
        free(module);
    }
}

int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return 0;
    }

    struct lys_module *module = create_dummy_module(ctx);
    if (!module) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    struct lyd_node *parent = NULL;
    struct lyd_node *node = NULL;

    const char *name = "dummy-list";
    const char *keys = "[key1='val1'][key2='val2']";
    uint32_t options = 0;

    // Fuzz lyd_new_list2
    lyd_new_list2(parent, module, name, keys, options, &node);

    const void *key_values[] = { "val1", "val2" };
    uint32_t value_sizes_bits[] = { 0, 0 };

    // Fuzz lyd_new_list3
    lyd_new_list3(parent, module, name, key_values, value_sizes_bits, options, &node);

    const char *value = "dummy-value";

    // Fuzz lyd_new_term
    lyd_new_term(parent, module, name, value, options, &node);

    struct lyd_node *tree = NULL;
    struct lyd_node *diff = NULL;

    // Fuzz lyd_validate_module
    lyd_validate_module(&tree, module, 0, &diff);

    struct lyd_node *child = NULL;

    // Fuzz lyd_insert_child
    lyd_insert_child(parent, child);

    // Fuzz lyd_new_list
    lyd_new_list(parent, module, name, options, &node, "val1", "val2");

    free_dummy_module(module);
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

        LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    