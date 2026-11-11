#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libyang/src/context.h"

// Helper function to create a dummy context
static struct ly_ctx *create_dummy_context() {
    struct ly_ctx *ctx = NULL;
    ly_ctx_new(NULL, 0, &ctx);
    return ctx;
}

// Helper function to free a dummy context
static void free_dummy_context(struct ly_ctx *ctx) {
    if (ctx) {
        ly_ctx_destroy(ctx);
    }
}

int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a dummy context
    struct ly_ctx *ctx = create_dummy_context();
    if (!ctx) {
        return 0;
    }

    // Prepare strings for namespace, revision, and name
    char *ns = NULL;
    char *revision = NULL;
    char *name = NULL;
    char *features[2] = {NULL, NULL};

    if (Size > 1) {
        ns = strndup((const char *)Data, Size / 3);
        revision = strndup((const char *)(Data + Size / 3), Size / 3);
        name = strndup((const char *)(Data + 2 * (Size / 3)), Size / 3);
    }

    // Invoke the target API functions
    struct lys_module *module;

    // ly_ctx_get_module_ns
    module = ly_ctx_get_module_ns(ctx, ns, revision);

    // ly_ctx_get_module_implemented
    module = ly_ctx_get_module_implemented(ctx, name);

    // ly_ctx_get_module_latest_ns
    module = ly_ctx_get_module_latest_ns(ctx, ns);

    // ly_ctx_get_module_latest
    module = ly_ctx_get_module_latest(ctx, name);

    // ly_ctx_load_module
    module = ly_ctx_load_module(ctx, name, revision, (const char **)features);

    // ly_ctx_get_module_implemented_ns
    module = ly_ctx_get_module_implemented_ns(ctx, ns);

    // Free allocated memory
    free(ns);
    free(revision);
    free(name);

    // Free the dummy context
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

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
