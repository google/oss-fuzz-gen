// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_dup_single at tree_data.c:2510:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "parser_data.h"
#include "tree_data.h"
#include "libyang.h"

static struct lys_module *create_dummy_module(struct ly_ctx *ctx) {
    struct lys_module *mod = malloc(sizeof(struct lys_module));
    if (!mod) {
        return NULL;
    }
    memset(mod, 0, sizeof(struct lys_module));
    mod->ctx = ctx;
    mod->name = "dummy-module";
    return mod;
}

static struct lyd_node *create_dummy_node(struct lys_module *mod) {
    struct lyd_node *node = malloc(sizeof(struct lyd_node));
    if (!node) {
        return NULL;
    }
    memset(node, 0, sizeof(struct lyd_node));
    struct lysc_node *schema = malloc(sizeof(struct lysc_node));
    if (!schema) {
        free(node);
        return NULL;
    }
    memset(schema, 0, sizeof(struct lysc_node));
    schema->module = mod;
    node->schema = schema;
    return node;
}

int LLVMFuzzerTestOneInput_62(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) {
        return 0;
    }

    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return 0;
    }

    struct lys_module *mod = create_dummy_module(ctx);
    if (!mod) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    struct lyd_node *node = create_dummy_node(mod);
    if (!node) {
        free(mod);
        ly_ctx_destroy(ctx);
        return 0;
    }

    struct lyd_node *parent = create_dummy_node(mod);
    if (!parent) {
        free(node->schema);
        free(node);
        free(mod);
        ly_ctx_destroy(ctx);
        return 0;
    }

    uint32_t options = *((uint32_t *)Data);
    struct lyd_node *dup = NULL;

    lyd_dup_single(node, parent, options, &dup);

    if (dup) {
        free(dup->schema);
        free(dup);
    }

    free(parent->schema);
    free(parent);
    free(node->schema);
    free(node);
    free(mod);
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

        LLVMFuzzerTestOneInput_62(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    