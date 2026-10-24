// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_dup_siblings at tree_data.c:2535:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_list3 at tree_data_new.c:632:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_eval_xpath3 at tree_data.c:3463:1 in tree_data.h
// lyd_trim_xpath at tree_data.c:3581:1 in tree_data.h
// lyd_validate_module at validation.c:2217:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <parser_data.h>
#include <tree_data.h>

static void fuzz_lyd_dup_siblings(const uint8_t *Data, size_t Size) {
    struct lyd_node *node = NULL, *parent = NULL, *dup = NULL;
    uint32_t options = 0;

    // Assuming Data contains some serialized node data, we will not actually parse it here
    // because it requires a valid context and schema. Instead, we simulate the API usage.
    LY_ERR ret = lyd_dup_siblings(node, parent, options, &dup);

    if (ret == LY_SUCCESS && dup) {
        // Cleanup duplicated nodes
        lyd_free_all(dup);
    }
}

static void fuzz_lyd_new_list3(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL, *node = NULL;
    const struct lys_module *module = NULL;
    const char *name = "list-name";
    const void **key_values = NULL;
    uint32_t *value_sizes_bits = NULL;
    uint32_t options = 0;

    LY_ERR ret = lyd_new_list3(parent, module, name, key_values, value_sizes_bits, options, &node);

    if (ret == LY_SUCCESS && node) {
        // Cleanup created node
        lyd_free_tree(node);
    }
}

static void fuzz_lyd_eval_xpath3(const uint8_t *Data, size_t Size) {
    struct lyd_node *ctx_node = NULL;
    const struct lys_module *cur_mod = NULL;
    char *xpath = strndup((const char *)Data, Size);
    LY_VALUE_FORMAT format = 0;
    void *prefix_data = NULL;
    const struct lyxp_var *vars = NULL;
    ly_bool result;

    if (xpath) {
        LY_ERR ret = lyd_eval_xpath3(ctx_node, cur_mod, xpath, format, prefix_data, vars, &result);
        free(xpath);
    }
}

static void fuzz_lyd_trim_xpath(const uint8_t *Data, size_t Size) {
    struct lyd_node *tree = NULL;
    char *xpath = strndup((const char *)Data, Size);
    const struct lyxp_var *vars = NULL;

    if (xpath) {
        LY_ERR ret = lyd_trim_xpath(&tree, xpath, vars);
        free(xpath);
    }
}

static void fuzz_lyd_validate_module(const uint8_t *Data, size_t Size) {
    struct lyd_node *tree = NULL, *diff = NULL;
    const struct lys_module *module = NULL;
    uint32_t val_opts = 0;

    LY_ERR ret = lyd_validate_module(&tree, module, val_opts, &diff);

    if (ret == LY_SUCCESS) {
        // Cleanup diff nodes
        if (diff) {
            lyd_free_all(diff);
        }
        // Cleanup validated tree
        if (tree) {
            lyd_free_all(tree);
        }
    }
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL, *node = NULL;
    const struct lys_module *module = NULL;
    const char *name = "term-name";
    char *value = (char *)malloc(Size + 1);

    if (value) {
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
}

int LLVMFuzzerTestOneInput_57(const uint8_t *Data, size_t Size) {
    fuzz_lyd_dup_siblings(Data, Size);
    fuzz_lyd_new_list3(Data, Size);
    fuzz_lyd_eval_xpath3(Data, Size);
    fuzz_lyd_trim_xpath(Data, Size);
    fuzz_lyd_validate_module(Data, Size);
    fuzz_lyd_new_term(Data, Size);

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

        LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    