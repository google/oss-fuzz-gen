#include <sys/stat.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/libyang/src/parser_data.h"
#include "/src/libyang/src/tree_data.h"
#include "/src/libyang/src/context.h" // Include the correct header for ly_ctx_new and ly_ctx_destroy

static struct lyd_node *create_dummy_node(struct ly_ctx *ctx) {
    struct lyd_node *node = malloc(sizeof(struct lyd_node));
    if (!node) {
        return NULL;
    }
    memset(node, 0, sizeof(struct lyd_node));
    node->schema = lys_find_path(ctx, NULL, "/dummy-schema", 0); // Find a valid schema node
    if (!node->schema) {
        free(node);
        return NULL;
    }
    return node;
}

static void free_dummy_node(struct lyd_node *node) {
    if (node) {
        free(node);
    }
}

int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Prepare dummy context
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return 0;
    }

    // Prepare dummy nodes
    struct lyd_node *node = create_dummy_node(ctx);
    if (!node) {
        ly_ctx_destroy(ctx);
        return 0; // Memory allocation failed
    }

    // Prepare a dummy file for lyd_parse_data_path
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        ly_ctx_destroy(ctx);
        free_dummy_node(node);
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Fuzz lyd_child
    struct lyd_node *child = lyd_child(node);

    // Ensure node->schema is not NULL for lyd_find_path
    if (node->schema) {
        // Fuzz lyd_find_path
        struct lyd_node *match = NULL;
        lyd_find_path(node, (const char *)Data, 0, &match);
    }

    // Fuzz lyd_child_any
    struct lyd_node *child_any = lyd_child_any(node);

    // Fuzz lyd_node_schema
    const struct lysc_node *schema = lyd_node_schema(node);

    // Fuzz lyd_parse_data_path
    struct lyd_node *tree = NULL;
    lyd_parse_data_path(ctx, "./dummy_file", 0, 0, 0, &tree);

    // Fuzz lyd_get_value
    const char *value = lyd_get_value(node);

    // Cleanup
    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
    free_dummy_node(node);

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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
