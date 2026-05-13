#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libyang.h>  // Corrected include path for libyang

int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node1 = NULL, *node2 = NULL;
    LY_ERR err;
    char *schema = "module a {namespace urn:a;prefix a;container c {leaf l {type string;}}}";
    char *data1 = "<c xmlns=\"urn:a\"><l>test1</l></c>";
    char *data2 = "<c xmlns=\"urn:a\"><l>test2</l></c>";

    // Create a new context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Parse schema
    err = lys_parse_mem(ctx, schema, LYS_IN_YANG, NULL);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse schema\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Parse data1
    err = lyd_parse_data_mem(ctx, data1, LYD_XML, LYD_PARSE_ONLY, LYD_VALIDATE_PRESENT, &node1);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse data1\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Parse data2
    err = lyd_parse_data_mem(ctx, data2, LYD_XML, LYD_PARSE_ONLY, LYD_VALIDATE_PRESENT, &node2);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse data2\n");
        lyd_free_all(node1);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Call the function-under-test
    err = lyd_insert_before(node1, node2);

    // Clean up
    lyd_free_all(node1);
    lyd_free_all(node2);
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

    LLVMFuzzerTestOneInput_111(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
