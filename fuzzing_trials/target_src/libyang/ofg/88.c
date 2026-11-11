#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libyang.h>  // Include libyang directly
#include <context.h>  // Include for ly_ctx related functions
#include <tree_schema.h>  // Include for lys_module related functions
#include <parser_schema.h>  // Include for lys_parse_mem function

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    char *namespace = NULL;
    const struct lys_module *module = NULL;  // Use 'const' as per libyang API
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Load a basic schema into the context
    const char *schema = "<module name='test' xmlns='urn:ietf:params:xml:ns:yang:yin:1'>"
                         "<namespace uri='urn:test'/><prefix value='t'/></module>";
    err = lys_parse_mem(ctx, schema, LYS_IN_YIN, NULL);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse schema\n");
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Allocate memory for the namespace string and copy fuzz data into it
    namespace = (char *)malloc(size + 1);
    if (namespace == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(namespace, data, size);
    namespace[size] = '\0';

    // Call the function-under-test
    module = ly_ctx_get_module_implemented_ns(ctx, namespace);

    // Clean up
    free(namespace);
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

    LLVMFuzzerTestOneInput_88(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
