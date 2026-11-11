// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_new_list3 at tree_data_new.c:632:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_dup_siblings_to_ctx at tree_data.c:2547:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_opaq at tree_data_new.c:878:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_implicit_all at tree_data_new.c:2010:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tree_data.h>

static void fuzz_lyd_new_list3(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    const char *name = "list-name";
    const void **key_values = NULL;
    uint32_t *value_sizes_bits = NULL;
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    lyd_new_list3(parent, module, name, key_values, value_sizes_bits, options, &node);
    lyd_free_tree(node);
}

static void fuzz_lyd_dup_siblings_to_ctx(const uint8_t *Data, size_t Size) {
    const struct lyd_node *node = NULL;
    const struct ly_ctx *trg_ctx = NULL;
    struct lyd_node *parent = NULL;
    uint32_t options = 0;
    struct lyd_node *dup = NULL;

    lyd_dup_siblings_to_ctx(node, trg_ctx, parent, options, &dup);
    lyd_free_tree(dup);
}

static void fuzz_lyd_new_opaq(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct ly_ctx *ctx = NULL;
    const char *name = "opaq-name";
    const char *value = NULL;
    const char *prefix = NULL;
    const char *module_name = NULL;
    struct lyd_node *node = NULL;

    lyd_new_opaq(parent, ctx, name, value, prefix, module_name, &node);
    lyd_free_tree(node);
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    struct lys_module module;
    module.name = "module-name";
    const char *name = "term-name";
    char *value = (char *)malloc(Size + 1);
    if (!value) return;
    memcpy(value, Data, Size);
    value[Size] = '\0';
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    lyd_new_term(parent, &module, name, value, options, &node);
    free(value);
    lyd_free_tree(node);
}

static void fuzz_lyd_new_path(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct ly_ctx *ctx = NULL;
    const char *path = "/example-module:container/list";
    char *value = (char *)malloc(Size + 1);
    if (!value) return;
    memcpy(value, Data, Size);
    value[Size] = '\0';
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    lyd_new_path(parent, ctx, path, value, options, &node);
    free(value);
    lyd_free_tree(node);
}

static void fuzz_lyd_new_implicit_all(const uint8_t *Data, size_t Size) {
    struct lyd_node *tree = NULL;
    const struct ly_ctx *ctx = NULL;
    uint32_t implicit_options = 0;
    struct lyd_node *diff = NULL;

    lyd_new_implicit_all(&tree, ctx, implicit_options, &diff);
    lyd_free_tree(tree);
    lyd_free_tree(diff);
}

int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size) {
    fuzz_lyd_new_list3(Data, Size);
    fuzz_lyd_dup_siblings_to_ctx(Data, Size);
    fuzz_lyd_new_opaq(Data, Size);
    fuzz_lyd_new_term(Data, Size);
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

        LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    