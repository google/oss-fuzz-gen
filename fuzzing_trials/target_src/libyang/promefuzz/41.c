// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_insert_sibling at tree_data.c:1114:1 in tree_data.h
// lyd_free_siblings at tree_data_free.c:305:1 in tree_data.h
// lyd_child at tree_data.h:1032:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_unlink_tree at tree_data.c:1293:1 in tree_data.h
// lyd_dup_siblings at tree_data.c:2535:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "tree_data.h"

static struct lyd_node *create_dummy_node() {
    struct lyd_node *node = (struct lyd_node *)malloc(sizeof(struct lyd_node));
    if (!node) {
        return NULL;
    }
    memset(node, 0, sizeof(struct lyd_node));
    
    struct lysc_node *schema = (struct lysc_node *)malloc(sizeof(struct lysc_node));
    if (!schema) {
        free(node);
        return NULL;
    }
    memset(schema, 0, sizeof(struct lysc_node));
    
    struct lys_module *module = (struct lys_module *)malloc(sizeof(struct lys_module));
    if (!module) {
        free(schema);
        free(node);
        return NULL;
    }
    memset(module, 0, sizeof(struct lys_module));
    module->name = "dummy_module";
    
    ((struct lysc_node *)schema)->module = module;
    node->schema = schema;
    
    return node;
}

int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) {
        return 0;
    }

    struct lyd_node *node1 = create_dummy_node();
    struct lyd_node *node2 = create_dummy_node();
    struct lyd_node *node3 = create_dummy_node();
    struct lyd_node *sibling = NULL;
    struct lyd_node *first = NULL;
    LY_ERR ret;

    if (!node1 || !node2 || !node3) {
        free(node1);
        free(node2);
        free(node3);
        return 0;
    }

    node1->next = node2;
    node2->prev = node1;
    node2->next = node3;
    node3->prev = node2;

    // Fuzzing `lyd_insert_sibling`
    ret = lyd_insert_sibling(sibling, node1, &first);

    // Fuzzing `lyd_free_siblings`
    lyd_free_siblings(node1);

    // Fuzzing `lyd_child`
    struct lyd_node *child = lyd_child(node1);

    // Fuzzing `lyd_free_all`
    lyd_free_all(node1);

    // Fuzzing `lyd_unlink_tree`
    ret = lyd_unlink_tree(node1);

    // Fuzzing `lyd_dup_siblings`
    ret = lyd_dup_siblings(node1, NULL, 0, &first);

    free(node1);
    free(node2);
    free(node3);

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
    