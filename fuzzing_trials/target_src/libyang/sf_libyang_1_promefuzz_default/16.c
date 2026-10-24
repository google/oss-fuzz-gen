// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_insert_child at tree_data.c:1095:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_list at tree_data_new.c:528:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_list2 at tree_data_new.c:581:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_list3 at tree_data_new.c:632:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_validate_module at validation.c:2217:1 in parser_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "parser_data.h"
#include "tree_data.h"

static void fuzz_lyd_new_list2(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    const char *name = "test-list";
    char *keys = NULL;
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (Size > 0) {
        keys = (char *)malloc(Size + 1);
        if (!keys) {
            return;
        }
        memcpy(keys, Data, Size);
        keys[Size] = '\0';
    }

    lyd_new_list2(parent, module, name, keys, options, &node);

    free(keys);
    lyd_free_tree(node);
}

static void fuzz_lyd_new_list3(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    const char *name = "test-list";
    const void **key_values = NULL;
    uint32_t *value_sizes_bits = NULL;
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (Size > 0) {
        key_values = (const void **)malloc(sizeof(void *) * Size);
        value_sizes_bits = (uint32_t *)malloc(sizeof(uint32_t) * Size);
        if (!key_values || !value_sizes_bits) {
            free(key_values);
            free(value_sizes_bits);
            return;
        }
        for (size_t i = 0; i < Size; ++i) {
            key_values[i] = &Data[i];
            value_sizes_bits[i] = 8;
        }
    }

    lyd_new_list3(parent, module, name, key_values, value_sizes_bits, options, &node);

    free(key_values);
    free(value_sizes_bits);
    lyd_free_tree(node);
}

static void fuzz_lyd_validate_module(const uint8_t *Data, size_t Size) {
    struct lyd_node *tree = NULL;
    const struct lys_module *module = NULL;
    uint32_t val_opts = 0;
    struct lyd_node *diff = NULL;

    lyd_validate_module(&tree, module, val_opts, &diff);

    lyd_free_tree(tree);
    lyd_free_tree(diff);
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    const char *name = "test-term";
    char *value = NULL;
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (Size > 0) {
        value = (char *)malloc(Size + 1);
        if (!value) {
            return;
        }
        memcpy(value, Data, Size);
        value[Size] = '\0';
    }

    lyd_new_term(parent, module, name, value, options, &node);

    free(value);
    lyd_free_tree(node);
}

static void fuzz_lyd_insert_child(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    struct lyd_node *node = NULL;

    lyd_insert_child(parent, node);

    lyd_free_tree(parent);
    lyd_free_tree(node);
}

static void fuzz_lyd_new_list(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    const char *name = "test-list";
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    lyd_new_list(parent, module, name, options, &node);

    lyd_free_tree(node);
}

int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    fuzz_lyd_new_list2(Data, Size);
    fuzz_lyd_new_list3(Data, Size);
    fuzz_lyd_validate_module(Data, Size);
    fuzz_lyd_new_term(Data, Size);
    fuzz_lyd_insert_child(Data, Size);
    fuzz_lyd_new_list(Data, Size);

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
    