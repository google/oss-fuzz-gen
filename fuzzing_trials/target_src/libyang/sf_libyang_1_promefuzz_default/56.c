// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_get_module_implemented at context.c:1009:1 in context.h
// ly_ctx_load_module at context.c:239:1 in context.h
// lyd_new_inner at tree_data_new.c:446:1 in tree_data.h
// lyd_new_opaq at tree_data_new.c:878:1 in tree_data.h
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_new_implicit_all at tree_data_new.c:2010:1 in tree_data.h
// lyd_new_any at tree_data_new.c:749:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "tree_data.h"
#include "libyang.h"

static struct ly_ctx *create_context() {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return NULL;
    }
    return ctx;
}

static struct lys_module *create_module(struct ly_ctx *ctx, const char *name) {
    struct lys_module *module = NULL;
    const char *features[] = {NULL};
    module = ly_ctx_get_module_implemented(ctx, name);
    if (!module) {
        module = ly_ctx_load_module(ctx, name, NULL, features);
    }
    return module;
}

static struct lyd_node *create_node() {
    struct lyd_node *node = NULL;
    return node;
}

int LLVMFuzzerTestOneInput_56(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct ly_ctx *ctx = create_context();
    if (!ctx) {
        return 0;
    }

    struct lys_module *module = create_module(ctx, "test-module");
    struct lyd_node *parent = create_node();
    struct lyd_node *node = NULL;
    const char *name = "test-node";
    const char *value = "test-value";
    const char *path = "/test-module:test-node";
    uint32_t options = 0;
    uint32_t implicit_options = 0;
    ly_bool output = 0;

    // Fuzzing lyd_new_inner
    lyd_new_inner(parent, module, name, output, &node);

    // Fuzzing lyd_new_opaq
    lyd_new_opaq(parent, ctx, name, value, NULL, "test-module", &node);

    // Fuzzing lyd_new_path
    lyd_new_path(parent, ctx, path, value, options, &node);

    // Fuzzing lyd_new_term
    lyd_new_term(parent, module, name, value, options, &node);

    // Fuzzing lyd_new_implicit_all
    lyd_new_implicit_all(&parent, ctx, implicit_options, &node);

    // Fuzzing lyd_new_any
    lyd_new_any(parent, module, name, NULL, value, 0, options, &node);

    // Cleanup
    lyd_free_all(parent);
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

        LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    