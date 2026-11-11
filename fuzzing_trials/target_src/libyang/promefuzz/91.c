// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_merge_module at tree_data.c:2856:1 in tree_data.h
// lyd_merge_tree at tree_data.c:2844:1 in tree_data.h
// lyd_node_schema at tree_data_common.c:1010:1 in tree_data.h
// lyd_node_module at tree_data_common.c:336:1 in tree_data.h
// lyd_new_any at tree_data_new.c:749:1 in tree_data.h
// lyd_owner_module at tree_data_common.c:299:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "tree_data.h"

static struct lyd_node *create_dummy_lyd_node() {
    struct lyd_node *node = (struct lyd_node *)malloc(sizeof(struct lyd_node));
    if (node) {
        memset(node, 0, sizeof(struct lyd_node));
    }
    return node;
}

static struct lys_module *create_dummy_lys_module() {
    struct lys_module *module = (struct lys_module *)malloc(sizeof(struct lys_module));
    if (module) {
        memset(module, 0, sizeof(struct lys_module));
    }
    return module;
}

int LLVMFuzzerTestOneInput_91(const uint8_t *Data, size_t Size) {
    // Prepare dummy nodes and module
    struct lyd_node *target = create_dummy_lyd_node();
    struct lyd_node *source = create_dummy_lyd_node();
    struct lys_module *mod = create_dummy_lys_module();

    if (!target || !source || !mod) {
        free(target);
        free(source);
        free(mod);
        return 0;
    }

    // Fuzzing options
    uint16_t options = 0;
    if (Size >= sizeof(options)) {
        memcpy(&options, Data, sizeof(options));
        Data += sizeof(options);
        Size -= sizeof(options);
    }

    // Fuzz lyd_merge_module
    lyd_merge_module(&target, source, mod, NULL, NULL, options);

    // Fuzz lyd_merge_tree
    lyd_merge_tree(&target, source, options);

    // Fuzz lyd_node_schema
    const struct lysc_node *schema = lyd_node_schema(source);

    // Fuzz lyd_node_module
    const struct lys_module *module = lyd_node_module(source);

    // Fuzz lyd_new_any
    const char *name = "dummy_name";
    struct lyd_node *any_node = NULL;
    lyd_new_any(target, mod, name, NULL, NULL, 0, options, &any_node);

    // Fuzz lyd_owner_module
    const struct lys_module *owner_module = lyd_owner_module(source);

    // Cleanup
    free(target);
    free(source);
    free(mod);
    free(any_node);

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

        LLVMFuzzerTestOneInput_91(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    