// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new_ylpath at context.c:449:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_diff_siblings at diff.c:1435:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_set_ext_data_clb at context.c:837:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_new_list2 at tree_data_new.c:581:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_free_attr_siblings at tree_data_free.c:139:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_get_change_count at context.c:755:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "context.h"
#include "tree_data.h"

static void fuzz_lyd_new_list2(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    char *name = NULL;
    char *keys = NULL;
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (Size < 2) {
        return;
    }

    // Extract name and keys from Data
    size_t name_len = Data[0] % Size;
    size_t keys_len = Data[1] % Size;

    if (name_len + keys_len + 2 > Size) {
        return;
    }

    name = strndup((char *)&Data[2], name_len);
    keys = strndup((char *)&Data[2 + name_len], keys_len);

    // Call function
    lyd_new_list2(parent, module, name, keys, options, &node);

    // Clean up
    free(name);
    free(keys);
    lyd_free_tree(node);
}

static void fuzz_lyd_free_attr_siblings(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_attr *attr = NULL;

    // Create dummy context and attribute
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return;
    }

    attr = (struct lyd_attr *)malloc(sizeof(struct lyd_attr));
    if (!attr) {
        ly_ctx_destroy(ctx);
        return;
    }
    memset(attr, 0, sizeof(struct lyd_attr));

    // Call function
    lyd_free_attr_siblings(ctx, attr);

    // No need to free(attr) as it is already freed by lyd_free_attr_siblings
    ly_ctx_destroy(ctx);
}

static void fuzz_ly_ctx_get_change_count(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return;
    }

    // Call function
    uint16_t change_count = ly_ctx_get_change_count(ctx);

    // Use the value to prevent compiler optimization
    (void)change_count;

    // Clean up
    ly_ctx_destroy(ctx);
}

static void fuzz_ly_ctx_new_ylpath(const uint8_t *Data, size_t Size) {
    const char *search_dir = NULL;
    const char *path = "./dummy_file";
    LYD_FORMAT format = LYD_XML;
    int options = 0;
    struct ly_ctx *ctx = NULL;

    // Write data to a dummy file
    FILE *file = fopen(path, "wb");
    if (!file) {
        return;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Call function
    ly_ctx_new_ylpath(search_dir, path, format, options, &ctx);

    // Clean up
    ly_ctx_destroy(ctx);
}

static void fuzz_lyd_diff_siblings(const uint8_t *Data, size_t Size) {
    struct lyd_node *first = NULL;
    struct lyd_node *second = NULL;
    uint16_t options = 0;
    struct lyd_node *diff = NULL;

    // Call function
    lyd_diff_siblings(first, second, options, &diff);

    // Clean up
    lyd_free_tree(diff);
}

static void fuzz_ly_ctx_set_ext_data_clb(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return;
    }

    ly_ext_data_clb clb = NULL;
    void *user_data = NULL;

    // Call function
    ly_ctx_set_ext_data_clb(ctx, clb, user_data);

    // Clean up
    ly_ctx_destroy(ctx);
}

int LLVMFuzzerTestOneInput_72(const uint8_t *Data, size_t Size) {
    fuzz_lyd_new_list2(Data, Size);
    fuzz_lyd_free_attr_siblings(Data, Size);
    fuzz_ly_ctx_get_change_count(Data, Size);
    fuzz_ly_ctx_new_ylpath(Data, Size);
    fuzz_lyd_diff_siblings(Data, Size);
    fuzz_ly_ctx_set_ext_data_clb(Data, Size);

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

        LLVMFuzzerTestOneInput_72(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    