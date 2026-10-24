// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_insert_child at tree_data.c:1095:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_list2 at tree_data_new.c:581:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_any at tree_data_new.c:749:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_validate_module at validation.c:2217:1 in parser_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_unlink_tree at tree_data.c:1293:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parser_data.h"
#include "tree_data.h"

static void fuzz_lyd_new_list2(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    char name[] = "list-node";
    char keys[] = "[key1='val1'][key2='val2']";
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (Size > 0) {
        options = Data[0];
    }

    LY_ERR err = lyd_new_list2(parent, module, name, keys, options, &node);
    if (err != LY_SUCCESS) {
        // Handle error
    }

    lyd_free_tree(node);
}

static void fuzz_lyd_new_any(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    char name[] = "any-node";
    const struct lyd_node *child = NULL;
    char value[] = "<data>value</data>";
    uint32_t hints = 0;
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (Size > 0) {
        options = Data[0];
    }

    LY_ERR err = lyd_new_any(parent, module, name, child, value, hints, options, &node);
    if (err != LY_SUCCESS) {
        // Handle error
    }

    lyd_free_tree(node);
}

static void fuzz_lyd_validate_module(const uint8_t *Data, size_t Size) {
    struct lyd_node *tree = NULL;
    const struct lys_module *module = NULL;
    uint32_t val_opts = 0;
    struct lyd_node *diff = NULL;

    if (Size > 0) {
        val_opts = Data[0];
    }

    LY_ERR err = lyd_validate_module(&tree, module, val_opts, &diff);
    if (err != LY_SUCCESS) {
        // Handle error
    }

    lyd_free_tree(diff);
}

static void fuzz_lyd_unlink_tree(const uint8_t *Data, size_t Size) {
    struct lyd_node *node = NULL;

    LY_ERR err = lyd_unlink_tree(node);
    if (err != LY_SUCCESS) {
        // Handle error
    }

    lyd_free_tree(node);
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    char name[] = "term-node";
    char value[] = "term-value";
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (Size > 0) {
        options = Data[0];
    }

    LY_ERR err = lyd_new_term(parent, module, name, value, options, &node);
    if (err != LY_SUCCESS) {
        // Handle error
    }

    lyd_free_tree(node);
}

static void fuzz_lyd_insert_child(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    struct lyd_node *node = NULL;

    LY_ERR err = lyd_insert_child(parent, node);
    if (err != LY_SUCCESS) {
        // Handle error
    }

    lyd_free_tree(node);
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    fuzz_lyd_new_list2(Data, Size);
    fuzz_lyd_new_any(Data, Size);
    fuzz_lyd_validate_module(Data, Size);
    fuzz_lyd_unlink_tree(Data, Size);
    fuzz_lyd_new_term(Data, Size);
    fuzz_lyd_insert_child(Data, Size);

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

        LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    