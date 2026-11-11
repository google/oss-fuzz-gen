// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_implicit_all at tree_data_new.c:2010:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_dup_siblings_to_ctx at tree_data.c:2547:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_opaq at tree_data_new.c:878:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_inner at tree_data_new.c:446:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include "tree_data.h"

static void fuzz_lyd_dup_siblings_to_ctx(const uint8_t *Data, size_t Size) {
    struct lyd_node *node = NULL;
    struct ly_ctx *trg_ctx = NULL;
    struct lyd_node *parent = NULL;
    struct lyd_node *dup = NULL;

    uint32_t options = 0;
    LY_ERR ret = lyd_dup_siblings_to_ctx(node, trg_ctx, parent, options, &dup);

    if (ret == LY_SUCCESS && dup) {
        // Cleanup duplicated nodes
        lyd_free_all(dup);
    }
}

static void fuzz_lyd_new_opaq(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;

    char *name = "dummy_name";
    char *value = "dummy_value";
    char *prefix = "dummy_prefix";
    char *module_name = "dummy_module";

    LY_ERR ret = lyd_new_opaq(parent, ctx, name, value, prefix, module_name, &node);

    if (ret == LY_SUCCESS && node) {
        // Cleanup created node
        lyd_free_tree(node);
    }
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    struct lys_module *module = NULL;
    struct lyd_node *node = NULL;

    char *name = "dummy_name";
    char *value = malloc(Size + 1);
    if (!value) {
        return;
    }
    memcpy(value, Data, Size);
    value[Size] = '\0';

    uint32_t options = 0;
    LY_ERR ret = lyd_new_term(parent, module, name, value, options, &node);

    if (ret == LY_SUCCESS && node) {
        // Cleanup created node
        lyd_free_tree(node);
    }

    free(value);
}

static void fuzz_lyd_new_inner(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    struct lys_module *module = NULL;
    struct lyd_node *node = NULL;

    char *name = "dummy_name";
    ly_bool output = 0;

    LY_ERR ret = lyd_new_inner(parent, module, name, output, &node);

    if (ret == LY_SUCCESS && node) {
        // Cleanup created node
        lyd_free_tree(node);
    }
}

static void fuzz_lyd_new_path(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;

    char *path = "dummy_path";
    char *value = malloc(Size + 1);
    if (!value) {
        return;
    }
    memcpy(value, Data, Size);
    value[Size] = '\0';

    uint32_t options = 0;
    LY_ERR ret = lyd_new_path(parent, ctx, path, value, options, &node);

    if (ret == LY_SUCCESS && node) {
        // Cleanup created node
        lyd_free_tree(node);
    }

    free(value);
}

static void fuzz_lyd_new_implicit_all(const uint8_t *Data, size_t Size) {
    struct lyd_node *tree = NULL;
    struct ly_ctx *ctx = NULL;
    struct lyd_node *diff = NULL;

    uint32_t implicit_options = 0;
    LY_ERR ret = lyd_new_implicit_all(&tree, ctx, implicit_options, &diff);

    if (ret == LY_SUCCESS && diff) {
        // Cleanup diff nodes
        lyd_free_all(diff);
    }
}

int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    fuzz_lyd_dup_siblings_to_ctx(Data, Size);
    fuzz_lyd_new_opaq(Data, Size);
    fuzz_lyd_new_term(Data, Size);
    fuzz_lyd_new_inner(Data, Size);
    fuzz_lyd_new_path(Data, Size);
    fuzz_lyd_new_implicit_all(Data, Size);

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

        LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    