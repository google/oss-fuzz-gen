// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_change_term at tree_data_new.c:1208:1 in tree_data.h
// lyd_change_term_canon at tree_data_new.c:1216:1 in tree_data.h
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// lyd_value_validate at tree_data_common.c:601:1 in tree_data.h
// lyd_parse_data_mem at tree_data.c:210:1 in parser_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libyang.h>
#include "parser_data.h"
#include "tree_data.h"

static struct ly_ctx *create_context() {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return NULL;
    }
    return ctx;
}

static void cleanup_context(struct ly_ctx *ctx) {
    if (ctx) {
        ly_ctx_destroy(ctx);
    }
}

static void fuzz_lyd_parse_data_mem(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    if (!ctx) {
        return;
    }

    // Ensure null-termination for the data
    char *data = (char *)malloc(Size + 1);
    if (!data) {
        cleanup_context(ctx);
        return;
    }
    memcpy(data, Data, Size);
    data[Size] = '\0';

    LYD_FORMAT format = LYD_JSON;
    uint32_t parse_options = 0;
    uint32_t validate_options = 0;
    struct lyd_node *tree = NULL;

    lyd_parse_data_mem(ctx, data, format, parse_options, validate_options, &tree);
    lyd_free_all(tree);

    free(data);
    cleanup_context(ctx);
}

static void fuzz_lyd_value_validate(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct lysc_node)) {
        return;
    }

    const struct lysc_node *schema = (const struct lysc_node *)Data;
    const char *value = (const char *)(Data + sizeof(struct lysc_node));
    uint32_t value_len = Size - sizeof(struct lysc_node);
    const struct lyd_node *ctx_node = NULL;
    const struct lysc_type *realtype = NULL;
    const char *canonical = NULL;

    lyd_value_validate(schema, value, value_len, ctx_node, &realtype, &canonical);
}

static void fuzz_lyd_change_term(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct lyd_node)) {
        return;
    }

    struct lyd_node *term = (struct lyd_node *)Data;
    const char *val_str = (const char *)(Data + sizeof(struct lyd_node));

    lyd_change_term(term, val_str);
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct lys_module)) {
        return;
    }

    struct lyd_node *parent = NULL;
    const struct lys_module *module = (const struct lys_module *)Data;
    const char *name = "example-name";
    const char *value = (const char *)(Data + sizeof(struct lys_module));
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    lyd_new_term(parent, module, name, value, options, &node);
    lyd_free_all(node);
}

static void fuzz_lyd_new_path(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    if (!ctx) {
        return;
    }

    struct lyd_node *parent = NULL;
    const char *path = "/example-path";

    // Ensure null-termination for the value
    char *value = (char *)malloc(Size + 1);
    if (!value) {
        cleanup_context(ctx);
        return;
    }
    memcpy(value, Data, Size);
    value[Size] = '\0';

    uint32_t options = 0;
    struct lyd_node *node = NULL;

    lyd_new_path(parent, ctx, path, value, options, &node);
    lyd_free_all(node);

    free(value);
    cleanup_context(ctx);
}

static void fuzz_lyd_change_term_canon(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct lyd_node)) {
        return;
    }

    struct lyd_node *term = (struct lyd_node *)Data;
    const char *val_str = (const char *)(Data + sizeof(struct lyd_node));

    lyd_change_term_canon(term, val_str);
}

int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    fuzz_lyd_parse_data_mem(Data, Size);
    fuzz_lyd_value_validate(Data, Size);
    fuzz_lyd_change_term(Data, Size);
    fuzz_lyd_new_term(Data, Size);
    fuzz_lyd_new_path(Data, Size);
    fuzz_lyd_change_term_canon(Data, Size);
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

        LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    