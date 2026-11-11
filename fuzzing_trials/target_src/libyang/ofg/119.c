#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "/src/libyang/src/tree_data.h"
#include "/src/libyang/build/libyang/context.h"

int LLVMFuzzerTestOneInput_119(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *parent = NULL;
    struct lyd_node *child = NULL;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a dummy parent node
    const char *parent_schema = "module parent {namespace urn:tests:parent;prefix p;yang-version 1.1;"
                                "container parent {leaf parent-leaf {type string;}}}";
    lys_parse_mem(ctx, parent_schema, LYS_IN_YANG, NULL);
    parent = lyd_new_path(NULL, ctx, "/parent:parent", NULL, 0, 0);

    // Create a dummy child node
    const char *child_schema = "module child {namespace urn:tests:child;prefix c;yang-version 1.1;"
                               "container child {leaf child-leaf {type string;}}}";
    lys_parse_mem(ctx, child_schema, LYS_IN_YANG, NULL);
    child = lyd_new_path(NULL, ctx, "/child:child", NULL, 0, 0);

    // Insert child into parent
    if (parent && child) {
        lyd_insert_child(parent, child);
    }

    // Cleanup
    lyd_free_all(parent);
    lyd_free_all(child);
    ly_ctx_destroy(ctx);

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

    LLVMFuzzerTestOneInput_119(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
