// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_new_list2 at tree_data_new.c:581:1 in tree_data.h
// lyd_new_list3 at tree_data_new.c:632:1 in tree_data.h
// lyd_validate_module at validation.c:2217:1 in parser_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_insert_child at tree_data.c:1095:1 in tree_data.h
// lyd_new_list at tree_data_new.c:528:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "parser_data.h"
#include "tree_data.h"

// Dummy function implementations
LY_ERR lyd_new_list2_2(struct lyd_node *parent, const struct lys_module *module, const char *name,
                     const char *keys, uint32_t options, struct lyd_node **node) {
    return LY_SUCCESS;
}

LY_ERR lyd_new_list3_2(struct lyd_node *parent, const struct lys_module *module, const char *name,
                     const void **key_values, uint32_t *value_sizes_bits, uint32_t options, struct lyd_node **node) {
    return LY_SUCCESS;
}

LY_ERR lyd_validate_module_2(struct lyd_node **tree, const struct lys_module *module, uint32_t val_opts,
                           struct lyd_node **diff) {
    return LY_SUCCESS;
}

LY_ERR lyd_new_term_2(struct lyd_node *parent, const struct lys_module *module, const char *name,
                    const char *value, uint32_t options, struct lyd_node **node) {
    return LY_SUCCESS;
}

LY_ERR lyd_insert_child_2(struct lyd_node *parent, struct lyd_node *node) {
    return LY_SUCCESS;
}

LY_ERR lyd_new_list_2(struct lyd_node *parent, const struct lys_module *module, const char *name,
                    uint32_t options, struct lyd_node **node, ...) {
    return LY_SUCCESS;
}

static struct lyd_node* create_dummy_lyd_node() {
    return (struct lyd_node*)malloc(sizeof(struct lyd_node));
}

static struct lys_module* create_dummy_lys_module() {
    return (struct lys_module*)malloc(sizeof(struct lys_module));
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct lyd_node *parent = create_dummy_lyd_node();
    struct lys_module *module = create_dummy_lys_module();
    struct lyd_node *node = NULL;
    const char *name = "dummy_name";
    const char *keys = "[key1='val1'][key2='val2']";
    uint32_t options = 0;
    uint32_t val_opts = 0;
    const char *value = "dummy_value";
    const void *key_values[] = { "val1", "val2" };
    uint32_t value_sizes_bits[] = { 32, 32 };

    lyd_new_list2_2(parent, module, name, keys, options, &node);
    lyd_new_list3_2(parent, module, name, key_values, value_sizes_bits, options, &node);
    lyd_validate_module_2(&node, module, val_opts, &node);
    lyd_new_term_2(parent, module, name, value, options, &node);
    lyd_insert_child_2(parent, node);
    lyd_new_list_2(parent, module, name, options, &node, "val1", "val2");

    free(parent);
    free(module);
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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    