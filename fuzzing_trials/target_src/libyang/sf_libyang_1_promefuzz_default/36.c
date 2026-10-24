// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_parse_op at tree_data.c:352:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libyang.h>
#include <parser_data.h>
#include <tree_data.h>

static struct ly_ctx *create_context() {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return NULL;
    }
    return ctx;
}

static void free_context(struct ly_ctx *ctx) {
    if (ctx) {
        ly_ctx_destroy(ctx);
    }
}

static struct ly_in *create_input(const uint8_t *Data, size_t Size) {
    struct ly_in *in = NULL;
    char *data_copy = (char *)malloc(Size + 1);
    if (!data_copy) {
        return NULL;
    }
    memcpy(data_copy, Data, Size);
    data_copy[Size] = '\0';
    if (ly_in_new_memory(data_copy, &in) != LY_SUCCESS) {
        free(data_copy);
        return NULL;
    }
    // Transfer ownership of data_copy to libyang, so do not free it manually.
    return in;
}

static void free_input(struct ly_in *in) {
    if (in) {
        ly_in_free(in, 1);  // Pass 1 to also free the memory buffer
    }
}

int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    if (!ctx) {
        return 0;
    }

    struct ly_in *in = create_input(Data, Size);
    if (!in) {
        free_context(ctx);
        return 0;
    }

    struct lyd_node *tree = NULL, *op = NULL;
    struct lyd_node *parent = NULL;  // Assuming no parent for RPC/notification
    LYD_FORMAT format = LYD_XML;    // Default format
    enum lyd_type data_type = LYD_TYPE_RPC_NETCONF;  // Example data type
    uint32_t parse_options = 0;

    // Call the target function
    lyd_parse_op(ctx, parent, in, format, data_type, parse_options, &tree, &op);

    // Clean up
    lyd_free_all(tree);
    lyd_free_all(op);
    free_input(in);
    free_context(ctx);

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

        LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    