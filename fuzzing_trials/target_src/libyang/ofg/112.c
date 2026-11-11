#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libyang.h> // Corrected header file

int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    struct lyd_attr *attr = NULL;
    const char *module_data = "module test {namespace urn:test;prefix t;container c {leaf l {type string;}}}";
    const char *attr_name = "attr-name";
    const char *attr_value = "attr-value";
    LY_ERR err;

    // Initialize libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create libyang context\n");
        return 0;
    }

    // Parse module data
    if (lys_parse_mem(ctx, module_data, LYS_IN_YANG, NULL) == NULL) {
        fprintf(stderr, "Failed to parse module data\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Create a new data tree node
    node = lyd_new_path(NULL, ctx, "/test:c/l", (void *)"initial-value", 0, 0);
    if (!node) {
        fprintf(stderr, "Failed to create data tree node\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Use the fuzzing data to create an attribute name and value
    char *fuzz_attr_name = malloc(size + 1);
    char *fuzz_attr_value = malloc(size + 1);
    if (!fuzz_attr_name || !fuzz_attr_value) {
        fprintf(stderr, "Memory allocation failed\n");
        lyd_free_all(node);
        ly_ctx_destroy(ctx);
        return 0;
    }

    memcpy(fuzz_attr_name, data, size);
    memcpy(fuzz_attr_value, data, size);
    fuzz_attr_name[size] = '\0';
    fuzz_attr_value[size] = '\0';

    // Call the function-under-test
    lyd_new_attr2(node, attr_name, fuzz_attr_name, fuzz_attr_value, &attr);

    // Clean up
    lyd_free_all(node);
    ly_ctx_destroy(ctx);
    free(fuzz_attr_name);
    free(fuzz_attr_value);

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

    LLVMFuzzerTestOneInput_112(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
