// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_find_path at tree_data.c:3700:1 in tree_data.h
// lyd_dup_siblings at tree_data.c:2535:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_eval_xpath3 at tree_data.c:3463:1 in tree_data.h
// lyd_change_meta at tree_data_new.c:1224:1 in tree_data.h
// lyd_trim_xpath at tree_data.c:3581:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "tree_data.h"

static void fuzz_lyd_find_path(const uint8_t *Data, size_t Size) {
    struct lyd_node *ctx_node = NULL; // Assuming a valid context node is available
    char *path = strndup((const char *)Data, Size);
    ly_bool output = 0;
    struct lyd_node *match = NULL;

    if (!path) {
        return;
    }

    LY_ERR ret = lyd_find_path(ctx_node, path, output, &match);
    if (ret == LY_SUCCESS) {
        // Handle success case if needed
    }

    free(path);
}

static void fuzz_lyd_dup_siblings(const uint8_t *Data, size_t Size) {
    struct lyd_node *node = NULL; // Assuming a valid node is available
    struct lyd_node *parent = NULL;
    uint32_t options = 0;
    struct lyd_node *dup = NULL;

    LY_ERR ret = lyd_dup_siblings(node, parent, options, &dup);
    if (ret == LY_SUCCESS) {
        // Handle success case if needed
    }

    // Assuming cleanup is needed for dup
    if (dup) {
        lyd_free_all(dup);
    }
}

static void fuzz_lyd_eval_xpath3(const uint8_t *Data, size_t Size) {
    struct lyd_node *ctx_node = NULL; // Assuming a valid context node is available
    struct lys_module *cur_mod = NULL; // Assuming a valid module is available
    char *xpath = strndup((const char *)Data, Size);
    LY_VALUE_FORMAT format = 0;
    void *prefix_data = NULL;
    struct lyxp_var *vars = NULL;
    ly_bool result;

    if (!xpath) {
        return;
    }

    LY_ERR ret = lyd_eval_xpath3(ctx_node, cur_mod, xpath, format, prefix_data, vars, &result);
    if (ret == LY_SUCCESS) {
        // Handle success case if needed
    }

    free(xpath);
}

static void fuzz_lyd_change_meta(const uint8_t *Data, size_t Size) {
    struct lyd_meta *meta = NULL; // Assuming a valid metadata is available
    char *val_str = strndup((const char *)Data, Size);

    if (!val_str) {
        return;
    }

    LY_ERR ret = lyd_change_meta(meta, val_str);
    if (ret == LY_SUCCESS) {
        // Handle success case if needed
    }

    free(val_str);
}

static void fuzz_lyd_trim_xpath(const uint8_t *Data, size_t Size) {
    struct lyd_node *tree = NULL; // Assuming a valid tree is available
    char *xpath = strndup((const char *)Data, Size);
    struct lyxp_var *vars = NULL;

    if (!xpath) {
        return;
    }

    LY_ERR ret = lyd_trim_xpath(&tree, xpath, vars);
    if (ret == LY_SUCCESS) {
        // Handle success case if needed
    }

    // Assuming cleanup is needed for tree
    if (tree) {
        lyd_free_all(tree);
    }

    free(xpath);
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL; // Assuming a valid parent node is available
    struct lys_module *module = NULL; // Assuming a valid module is available
    char *name = "dummy_name";
    char *value = strndup((const char *)Data, Size);
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (!value) {
        return;
    }

    LY_ERR ret = lyd_new_term(parent, module, name, value, options, &node);
    if (ret == LY_SUCCESS) {
        // Handle success case if needed
    }

    // Assuming cleanup is needed for node
    if (node) {
        lyd_free_all(node);
    }

    free(value);
}

int LLVMFuzzerTestOneInput_53(const uint8_t *Data, size_t Size) {
    fuzz_lyd_find_path(Data, Size);
    fuzz_lyd_dup_siblings(Data, Size);
    fuzz_lyd_eval_xpath3(Data, Size);
    fuzz_lyd_change_meta(Data, Size);
    fuzz_lyd_trim_xpath(Data, Size);
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

        LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    