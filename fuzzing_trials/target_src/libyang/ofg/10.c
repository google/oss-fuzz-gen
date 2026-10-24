#include <libyang.h> // Correct header file for libyang
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    struct lyd_meta *meta = NULL;
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    const char *schema = "module test {namespace urn:test;prefix t;leaf leaf1 {type string;}}";
    const char *data_str = "<leaf1 xmlns=\"urn:test\">test</leaf1>";

    // Initialize the libyang context
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return 0;
    }

    // Parse the schema
    if (lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL) == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Parse the data to create a data tree
    if (lyd_parse_data_mem(ctx, data_str, LYD_XML, 0, LYD_VALIDATE_PRESENT, &node) != LY_SUCCESS) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Allocate and initialize a lyd_meta structure
    meta = (struct lyd_meta *)malloc(sizeof(struct lyd_meta));
    if (!meta) {
        lyd_free_all(node);
        ly_ctx_destroy(ctx);
        return 0;
    }
    memset(meta, 0, sizeof(struct lyd_meta));

    // Fuzzing the lyd_free_meta_single function
    lyd_free_meta_single(meta);

    // Cleanup
    lyd_free_all(node);
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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
