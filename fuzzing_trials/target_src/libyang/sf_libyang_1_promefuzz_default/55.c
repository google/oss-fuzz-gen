// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_new_any at tree_data_new.c:749:1 in tree_data.h
// lyd_new_inner at tree_data_new.c:446:1 in tree_data.h
// lyd_new_opaq at tree_data_new.c:878:1 in tree_data.h
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_new_implicit_all at tree_data_new.c:2010:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <tree_data.h>

static void fuzz_lyd_new_inner(struct lyd_node *parent, const struct lys_module *module, const uint8_t *Data, size_t Size) {
    char *name = strndup((const char *)Data, Size);
    if (!name) {
        return;
    }

    ly_bool output = Size % 2;
    struct lyd_node *node = NULL;
    lyd_new_inner(parent, module, name, output, &node);

    free(name);
}

static void fuzz_lyd_new_opaq(struct lyd_node *parent, const struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    char *name = strndup((const char *)Data, Size);
    char *value = strndup((const char *)Data, Size / 2);
    char *prefix = strndup((const char *)Data + Size / 2, Size / 4);
    char *module_name = strndup((const char *)Data + 3 * Size / 4, Size / 4);

    if (!name || !value || !prefix || !module_name) {
        free(name);
        free(value);
        free(prefix);
        free(module_name);
        return;
    }

    struct lyd_node *node = NULL;
    lyd_new_opaq(parent, ctx, name, value, prefix, module_name, &node);

    free(name);
    free(value);
    free(prefix);
    free(module_name);
}

static void fuzz_lyd_new_path(struct lyd_node *parent, const struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    char *path = strndup((const char *)Data, Size);
    char *value = strndup((const char *)Data, Size / 2);

    if (!path || !value) {
        free(path);
        free(value);
        return;
    }

    uint32_t options = 0;
    struct lyd_node *node = NULL;
    lyd_new_path(parent, ctx, path, value, options, &node);

    free(path);
    free(value);
}

static void fuzz_lyd_new_term(struct lyd_node *parent, const struct lys_module *module, const uint8_t *Data, size_t Size) {
    char *name = strndup((const char *)Data, Size);
    char *value = strndup((const char *)Data, Size / 2);

    if (!name || !value) {
        free(name);
        free(value);
        return;
    }

    uint32_t options = 0;
    struct lyd_node *node = NULL;
    lyd_new_term(parent, module, name, value, options, &node);

    free(name);
    free(value);
}

static void fuzz_lyd_new_implicit_all(struct lyd_node **tree, const struct ly_ctx *ctx) {
    uint32_t implicit_options = 0;
    struct lyd_node *diff = NULL;
    lyd_new_implicit_all(tree, ctx, implicit_options, &diff);
}

static void fuzz_lyd_new_any(struct lyd_node *parent, const struct lys_module *module, const uint8_t *Data, size_t Size) {
    char *name = strndup((const char *)Data, Size);
    char *value = strndup((const char *)Data, Size / 2);

    if (!name || !value) {
        free(name);
        free(value);
        return;
    }

    uint32_t hints = 0;
    uint32_t options = 0;
    struct lyd_node *node = NULL;
    lyd_new_any(parent, module, name, NULL, value, hints, options, &node);

    free(name);
    free(value);
}

int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *parent = NULL;
    struct lys_module *module = NULL;

    fuzz_lyd_new_inner(parent, module, Data, Size);
    fuzz_lyd_new_opaq(parent, ctx, Data, Size);
    fuzz_lyd_new_path(parent, ctx, Data, Size);
    fuzz_lyd_new_term(parent, module, Data, Size);
    fuzz_lyd_new_implicit_all(&parent, ctx);
    fuzz_lyd_new_any(parent, module, Data, Size);

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

        LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    