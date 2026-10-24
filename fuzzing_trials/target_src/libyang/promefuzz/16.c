// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_diff_apply_module at diff.c:1946:1 in tree_data.h
// lyd_diff_merge_module at diff.c:2995:1 in tree_data.h
// lyd_diff_merge_tree at diff.c:3018:1 in tree_data.h
// lyd_diff_merge_all at diff.c:3034:1 in tree_data.h
// lyd_diff_tree at diff.c:1429:1 in tree_data.h
// lyd_diff_siblings at diff.c:1435:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "tree_data.h"

static struct lyd_node* create_dummy_lyd_node() {
    struct lyd_node *node = malloc(sizeof(struct lyd_node));
    if (!node) {
        return NULL;
    }
    memset(node, 0, sizeof(struct lyd_node));
    node->prev = node; // Ensuring prev is not NULL
    return node;
}

static struct lys_module* create_dummy_lys_module() {
    struct lys_module *mod = malloc(sizeof(struct lys_module));
    if (!mod) {
        return NULL;
    }
    memset(mod, 0, sizeof(struct lys_module));
    return mod;
}

static void free_dummy_lyd_node(struct lyd_node *node) {
    if (node) {
        free(node);
    }
}

static void free_dummy_lys_module(struct lys_module *mod) {
    if (mod) {
        free(mod);
    }
}

int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct lyd_node *data = create_dummy_lyd_node();
    struct lyd_node *diff = create_dummy_lyd_node();
    struct lys_module *mod = create_dummy_lys_module();
    uint16_t options = Data[0];
    lyd_diff_cb diff_cb = NULL;
    void *cb_data = NULL;

    if (!data || !diff || !mod) {
        goto cleanup;
    }

    // Fuzz lyd_diff_apply_module
    lyd_diff_apply_module(&data, diff, mod, diff_cb, cb_data);

    // Fuzz lyd_diff_merge_module
    lyd_diff_merge_module(&diff, diff, mod, diff_cb, cb_data, options);

    // Fuzz lyd_diff_merge_tree
    lyd_diff_merge_tree(&diff, diff, diff, diff_cb, cb_data, options);

    // Fuzz lyd_diff_merge_all
    lyd_diff_merge_all(&diff, diff, options);

    // Fuzz lyd_diff_tree
    struct lyd_node *out_diff = NULL;
    lyd_diff_tree(data, diff, options, &out_diff);
    free_dummy_lyd_node(out_diff);

    // Fuzz lyd_diff_siblings
    lyd_diff_siblings(data, diff, options, &out_diff);
    free_dummy_lyd_node(out_diff);

cleanup:
    free_dummy_lyd_node(data);
    free_dummy_lyd_node(diff);
    free_dummy_lys_module(mod);

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

        LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    