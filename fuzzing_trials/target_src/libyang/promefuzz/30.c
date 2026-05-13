// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_get_module_ns at context.c:936:1 in context.h
// ly_ctx_get_module at context.c:943:1 in context.h
// ly_ctx_get_module_implemented at context.c:1009:1 in context.h
// ly_ctx_get_module_latest_ns at context.c:979:1 in context.h
// ly_ctx_get_module_latest at context.c:972:1 in context.h
// ly_ctx_load_module at context.c:239:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "context.h"

static char *create_string_from_data(const uint8_t *Data, size_t Size) {
    char *str = (char *)malloc(Size + 1);
    if (str) {
        memcpy(str, Data, Size);
        str[Size] = '\0';
    }
    return str;
}

int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Initialize context
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS || !ctx) {
        return 0;
    }

    // Create strings from the input data
    char *name = create_string_from_data(Data, Size);
    char *revision = create_string_from_data(Data, Size);
    char *namespace = create_string_from_data(Data, Size);

    if (!name || !revision || !namespace) {
        free(name);
        free(revision);
        free(namespace);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Fuzz ly_ctx_get_module_ns
    struct lys_module *mod_ns = ly_ctx_get_module_ns(ctx, namespace, revision);
    if (mod_ns) {
        // Use the module, if needed
    }

    // Fuzz ly_ctx_get_module
    struct lys_module *mod = ly_ctx_get_module(ctx, name, revision);
    if (mod) {
        // Use the module, if needed
    }

    // Fuzz ly_ctx_get_module_implemented
    struct lys_module *mod_impl = ly_ctx_get_module_implemented(ctx, name);
    if (mod_impl) {
        // Use the module, if needed
    }

    // Fuzz ly_ctx_get_module_latest_ns
    struct lys_module *mod_latest_ns = ly_ctx_get_module_latest_ns(ctx, namespace);
    if (mod_latest_ns) {
        // Use the module, if needed
    }

    // Fuzz ly_ctx_get_module_latest
    struct lys_module *mod_latest = ly_ctx_get_module_latest(ctx, name);
    if (mod_latest) {
        // Use the module, if needed
    }

    // Fuzz ly_ctx_load_module
    const char *features[] = {NULL};
    struct lys_module *loaded_mod = ly_ctx_load_module(ctx, name, revision, features);
    if (loaded_mod) {
        // Use the module, if needed
    }

    // Cleanup
    free(name);
    free(revision);
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

        LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    