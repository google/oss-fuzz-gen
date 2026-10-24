// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_change_term_canon at tree_data_new.c:1216:1 in tree_data.h
// lyd_change_term at tree_data_new.c:1208:1 in tree_data.h
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// lyd_value_validate at tree_data_common.c:601:1 in tree_data.h
// lyd_parse_data_mem at tree_data.c:210:1 in parser_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <libyang.h>
#include <parser_data.h>
#include <tree_data.h>

static void fuzz_lyd_parse_data_mem(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL;
    char *data = NULL;

    // Initialize context
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return;
    }

    // Allocate and copy data
    data = (char *)malloc(Size + 1);
    if (!data) {
        ly_ctx_destroy(ctx);
        return;
    }
    memcpy(data, Data, Size);
    data[Size] = '\0';

    // Fuzz lyd_parse_data_mem
    lyd_parse_data_mem(ctx, data, LYD_XML, 0, 0, &tree);

    // Cleanup
    lyd_free_all(tree);
    free(data);
    ly_ctx_destroy(ctx);
}

static void fuzz_lyd_value_validate(const uint8_t *Data, size_t Size) {
    const struct lysc_node *schema = NULL;  // Assuming a valid schema node is set up here
    struct lysc_type *realtype = NULL;
    const char *canonical = NULL;
    char *value = NULL;

    // Allocate and copy value
    value = (char *)malloc(Size + 1);
    if (!value) {
        return;
    }
    memcpy(value, Data, Size);
    value[Size] = '\0';

    // Fuzz lyd_value_validate
    lyd_value_validate(schema, value, Size, NULL, &realtype, &canonical);

    // Cleanup
    lydict_remove(NULL, canonical);
    free(value);
}

static void fuzz_lyd_change_term(const uint8_t *Data, size_t Size) {
    struct lyd_node *term = NULL;  // Assuming a valid term node is set up here
    char *val_str = NULL;

    // Allocate and copy val_str
    val_str = (char *)malloc(Size + 1);
    if (!val_str) {
        return;
    }
    memcpy(val_str, Data, Size);
    val_str[Size] = '\0';

    // Fuzz lyd_change_term
    lyd_change_term(term, val_str);

    // No specific cleanup needed for val_str
    free(val_str);
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;  // Assuming a valid parent node is set up here
    struct lys_module *module = NULL;  // Assuming a valid module is set up here
    struct lyd_node *node = NULL;
    char *value = NULL;

    // Allocate and copy value
    value = (char *)malloc(Size + 1);
    if (!value) {
        return;
    }
    memcpy(value, Data, Size);
    value[Size] = '\0';

    // Fuzz lyd_new_term
    lyd_new_term(parent, module, "test-name", value, 0, &node);

    // Cleanup
    lyd_free_all(node);
    free(value);
}

static void fuzz_lyd_new_path(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    char *path = NULL;

    // Initialize context
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return;
    }

    // Allocate and copy path
    path = (char *)malloc(Size + 1);
    if (!path) {
        ly_ctx_destroy(ctx);
        return;
    }
    memcpy(path, Data, Size);
    path[Size] = '\0';

    // Fuzz lyd_new_path
    lyd_new_path(parent, ctx, path, NULL, 0, &node);

    // Cleanup
    lyd_free_all(node);
    free(path);
    ly_ctx_destroy(ctx);
}

static void fuzz_lyd_change_term_canon(const uint8_t *Data, size_t Size) {
    struct lyd_node *term = NULL;  // Assuming a valid term node is set up here
    char *val_str = NULL;

    // Allocate and copy val_str
    val_str = (char *)malloc(Size + 1);
    if (!val_str) {
        return;
    }
    memcpy(val_str, Data, Size);
    val_str[Size] = '\0';

    // Fuzz lyd_change_term_canon
    lyd_change_term_canon(term, val_str);

    // No specific cleanup needed for val_str
    free(val_str);
}

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    fuzz_lyd_parse_data_mem(Data, Size);
    fuzz_lyd_value_validate(Data, Size);
    fuzz_lyd_change_term(Data, Size);
    fuzz_lyd_new_term(Data, Size);
    fuzz_lyd_new_path(Data, Size);
    fuzz_lyd_change_term_canon(Data, Size);
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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    