#include <string.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "/src/libyang/src/tree_data.h"
#include "/src/libyang/src/context.h"
#include "/src/libyang/src/set.h" // Added include for related declarations

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *parent = NULL;
    struct lyd_node *new_node = NULL;
    const struct lys_module *module = NULL;
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Load a module to get a valid lys_module pointer
    err = lys_parse_mem(ctx, "module test {namespace urn:test;prefix t; list mylist {key \"name\"; leaf name {type string;}}}", LYS_IN_YANG, &module);
    if (err != LY_SUCCESS || module == NULL) {
        fprintf(stderr, "Failed to parse module\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Prepare string inputs for the function
    const char *list_name = "mylist";
    const char *key_value = "test-key";

    // Call the function-under-test
    err = lyd_new_list2(parent, module, list_name, key_value, 0, &new_node);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create new list\n");
    }

    // Clean up
    lyd_free_all(new_node);
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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
