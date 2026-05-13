// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_set_options at context.c:626:1 in context.h
// ly_ctx_get_options at context.c:618:1 in context.h
// ly_ctx_get_modules_hash at context.c:763:1 in context.h
// ly_ctx_get_change_count at context.c:755:1 in context.h
// ly_ctx_get_module_iter at context.c:860:1 in context.h
// ly_ctx_free_parsed at context.c:1360:1 in context.h
// ly_ctx_internal_modules_count at context.c:1124:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "context.h"

static struct ly_ctx *create_dummy_context() {
    // Create a dummy context using libyang's context creation function
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return NULL;
    }
    return ctx;
}

static void free_dummy_context(struct ly_ctx *ctx) {
    // Free the dummy context using libyang's context destruction function
    if (ctx) {
        ly_ctx_destroy(ctx);
    }
}

int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) {
        return 0; // Not enough data to proceed
    }

    struct ly_ctx *ctx = create_dummy_context();
    if (!ctx) {
        return 0; // Failed to create context
    }

    // Use the first 4 bytes of data to set some options for the context
    uint32_t options = *((uint32_t *)Data);
    ly_ctx_set_options(ctx, options);

    // Fuzz ly_ctx_get_options
    uint32_t ctx_options = ly_ctx_get_options(ctx);

    // Fuzz ly_ctx_get_modules_hash
    uint32_t hash = ly_ctx_get_modules_hash(ctx);

    // Fuzz ly_ctx_get_change_count
    uint16_t change_count = ly_ctx_get_change_count(ctx);

    // Fuzz ly_ctx_get_module_iter
    uint32_t index = 0;
    struct lys_module *module;
    while ((module = ly_ctx_get_module_iter(ctx, &index)) != NULL) {
        // Iterate through modules
    }

    // Fuzz ly_ctx_free_parsed
    ly_ctx_free_parsed(ctx);

    // Fuzz ly_ctx_internal_modules_count
    uint32_t internal_modules_count = ly_ctx_internal_modules_count(ctx);

    // Clean up
    free_dummy_context(ctx);

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

        LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    