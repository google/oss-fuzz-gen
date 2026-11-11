// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
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
// lyd_insert_child at tree_data.c:1095:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <parser_data.h>
#include <tree_data.h>

static void fuzz_lyd_new_list2(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    const char *name = "list-node";
    const char *keys = "[key1='val1'][key2='val2']";
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (Size > 0) {
        keys = (const char *)Data;
    }

    lyd_new_list2(parent, module, name, keys, options, &node);

    if (node) {
        lyd_free_tree(node);
    }
}

static void fuzz_lyd_new_list3(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    const char *name = "list-node";
    const void *key_values[] = { "[key1='val1']", "[key2='val2']" };
    uint32_t value_sizes_bits[] = { 8, 8 };
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (Size > 0) {
        key_values[0] = Data;
    }

    lyd_new_list3(parent, module, name, key_values, value_sizes_bits, options, &node);

    if (node) {
        lyd_free_tree(node);
    }
}

static void fuzz_lyd_validate_module(const uint8_t *Data, size_t Size) {
    struct lyd_node *tree = NULL;
    const struct lys_module *module = NULL;
    uint32_t val_opts = 0;
    struct lyd_node *diff = NULL;

    lyd_validate_module(&tree, module, val_opts, &diff);

    if (tree) {
        lyd_free_tree(tree);
    }
    if (diff) {
        lyd_free_tree(diff);
    }
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    const char *name = "term-node";
    const char *value = "term-value";
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    // Ensure the data is null-terminated before using it as a string.
    char *value_buffer = NULL;
    if (Size > 0) {
        value_buffer = (char *)malloc(Size + 1);
        if (value_buffer) {
            memcpy(value_buffer, Data, Size);
            value_buffer[Size] = '\0';
            value = value_buffer;
        }
    }

    lyd_new_term(parent, module, name, value, options, &node);

    if (node) {
        lyd_free_tree(node);
    }

    free(value_buffer);
}

static void fuzz_lyd_insert_child(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    struct lyd_node *node = NULL;

    lyd_insert_child(parent, node);

    if (node) {
        lyd_free_tree(node);
    }
}

static void fuzz_lyd_new_list(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    const char *name = "list-node";
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    lyd_new_list(parent, module, name, options, &node);

    if (node) {
        lyd_free_tree(node);
    }
}

int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
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

        LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    