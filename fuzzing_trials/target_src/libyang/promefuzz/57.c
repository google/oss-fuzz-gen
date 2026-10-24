// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_parse_data_mem at tree_data.c:210:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_parse_data_mem at tree_data.c:210:1 in parser_data.h
// ly_ctx_new_yldata at context.c:497:1 in context.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_compiled_size at context.c:1388:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_get_yanglib_data at context.c:1216:1 in context.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new_ylmem at context.c:473:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_parse_data_mem at tree_data.c:210:1 in parser_data.h
// lyd_validate_all at validation.c:2202:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include "context.h"
#include "parser_data.h"

static int fuzz_ly_ctx_compiled_size(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    LY_ERR err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    int size = ly_ctx_compiled_size(ctx);
    if (size == -1) {
        // Handle error if needed
    }

    ly_ctx_destroy(ctx);
    return 0;
}

static int fuzz_ly_ctx_get_yanglib_data(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL;

    LY_ERR err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    err = ly_ctx_get_yanglib_data(ctx, &root, "%u", 0);
    if (err != LY_SUCCESS) {
        // Handle error if needed
    }

    lyd_free_all(root);
    ly_ctx_destroy(ctx);
    return 0;
}

static int fuzz_ly_ctx_new_ylmem(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    char *data = (char *)malloc(Size + 1);
    if (!data) {
        return 0;
    }
    memcpy(data, Data, Size);
    data[Size] = '\0';

    LY_ERR err = ly_ctx_new_ylmem(NULL, data, LYD_XML, 0, &ctx);
    if (err != LY_SUCCESS) {
        // Handle error if needed
    }

    ly_ctx_destroy(ctx);
    free(data);
    return 0;
}

static int fuzz_lyd_validate_all(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL, *diff = NULL;

    LY_ERR err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    char *data = (char *)malloc(Size + 1);
    if (!data) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data, Data, Size);
    data[Size] = '\0';

    err = lyd_parse_data_mem(ctx, data, LYD_XML, 0, 0, &tree);
    if (err == LY_SUCCESS) {
        err = lyd_validate_all(&tree, ctx, 0, &diff);
        if (err != LY_SUCCESS) {
            // Handle error if needed
        }
        lyd_free_all(diff);
    }

    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
    free(data);
    return 0;
}

static int fuzz_lyd_parse_data_mem(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL;

    LY_ERR err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    char *data = (char *)malloc(Size + 1);
    if (!data) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data, Data, Size);
    data[Size] = '\0';

    err = lyd_parse_data_mem(ctx, data, LYD_XML, 0, 0, &tree);
    if (err != LY_SUCCESS) {
        // Handle error if needed
    }

    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
    free(data);
    return 0;
}

static int fuzz_ly_ctx_new_yldata(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL;

    LY_ERR err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    char *data = (char *)malloc(Size + 1);
    if (!data) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data, Data, Size);
    data[Size] = '\0';

    err = lyd_parse_data_mem(ctx, data, LYD_XML, 0, 0, &tree);
    if (err == LY_SUCCESS) {
        err = ly_ctx_new_yldata(NULL, tree, 0, &ctx);
        if (err != LY_SUCCESS) {
            // Handle error if needed
        }
    }

    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
    free(data);
    return 0;
}

int LLVMFuzzerTestOneInput_57(const uint8_t *Data, size_t Size) {
    fuzz_ly_ctx_compiled_size(Data, Size);
    fuzz_ly_ctx_get_yanglib_data(Data, Size);
    fuzz_ly_ctx_new_ylmem(Data, Size);
    fuzz_lyd_validate_all(Data, Size);
    fuzz_lyd_parse_data_mem(Data, Size);
    fuzz_ly_ctx_new_yldata(Data, Size);
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

        LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    