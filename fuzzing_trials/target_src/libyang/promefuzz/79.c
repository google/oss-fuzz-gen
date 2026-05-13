// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_parse_data_path at tree_data.c:238:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new_ylmem at context.c:473:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_set_searchdir at context.c:85:1 in context.h
// ly_ctx_unset_searchdir at context.c:181:1 in context.h
// ly_ctx_new_ylpath at context.c:449:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new_yldata at context.c:497:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "context.h"
#include "parser_data.h"

static void fuzz_ly_ctx_new_ylmem(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;  // Ensure there is enough data

    const char *search_dir = NULL;
    char *yl_data = (char *)malloc(Size + 1);
    if (!yl_data) return;
    memcpy(yl_data, Data + 1, Size - 1);
    yl_data[Size - 1] = '\0';  // Null-terminate the input

    LYD_FORMAT format = (LYD_FORMAT)(Data[0] % 3); // Assuming 3 possible formats
    int options = 0;
    struct ly_ctx *ctx = NULL;

    ly_ctx_new_ylmem(search_dir, yl_data, format, options, &ctx);
    if (ctx) {
        ly_ctx_destroy(ctx);
    }
    free(yl_data);
}

static void fuzz_ly_ctx_set_searchdir(struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    char *search_dir = (char *)malloc(Size + 1);
    if (!search_dir) return;
    memcpy(search_dir, Data, Size);
    search_dir[Size] = '\0';

    ly_ctx_set_searchdir(ctx, search_dir);
    free(search_dir);
}

static void fuzz_ly_ctx_unset_searchdir(struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    char *value = (char *)malloc(Size + 1);
    if (!value) return;
    memcpy(value, Data, Size);
    value[Size] = '\0';

    ly_ctx_unset_searchdir(ctx, value);
    free(value);
}

static void fuzz_ly_ctx_new_ylpath(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    const char *search_dir = NULL;
    const char *path = "./dummy_file";
    LYD_FORMAT format = (LYD_FORMAT)(Data[0] % 3); // Assuming 3 possible formats
    int options = 0;
    struct ly_ctx *ctx = NULL;

    FILE *file = fopen(path, "wb");
    if (!file) return;
    fwrite(Data, 1, Size, file);
    fclose(file);

    ly_ctx_new_ylpath(search_dir, path, format, options, &ctx);
    if (ctx) {
        ly_ctx_destroy(ctx);
    }
}

static void fuzz_ly_ctx_new_yldata(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct lyd_node)) return;

    const char *search_dir = NULL;
    struct lyd_node *tree = (struct lyd_node *)Data;
    int options = 0;
    struct ly_ctx *ctx = NULL;

    ly_ctx_new_yldata(search_dir, tree, options, &ctx);
    if (ctx) {
        ly_ctx_destroy(ctx);
    }
}

static void fuzz_lyd_parse_data_path(struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    const char *path = "./dummy_file";
    LYD_FORMAT format = (LYD_FORMAT)(Data[0] % 3); // Assuming 3 possible formats
    uint32_t parse_options = 0;
    uint32_t validate_options = 0;
    struct lyd_node *tree = NULL;

    FILE *file = fopen(path, "wb");
    if (!file) return;
    fwrite(Data, 1, Size, file);
    fclose(file);

    lyd_parse_data_path(ctx, path, format, parse_options, validate_options, &tree);
    if (tree) {
        lyd_free_all(tree);
    }
}

int LLVMFuzzerTestOneInput_79(const uint8_t *Data, size_t Size) {
    fuzz_ly_ctx_new_ylmem(Data, Size);

    struct ly_ctx *ctx = NULL;
    ly_ctx_new(NULL, 0, &ctx);

    if (ctx) {
        fuzz_ly_ctx_set_searchdir(ctx, Data, Size);
        fuzz_ly_ctx_unset_searchdir(ctx, Data, Size);
        fuzz_ly_ctx_new_ylpath(Data, Size);
        fuzz_ly_ctx_new_yldata(Data, Size);
        fuzz_lyd_parse_data_path(ctx, Data, Size);

        ly_ctx_destroy(ctx);
    }

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

        LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    