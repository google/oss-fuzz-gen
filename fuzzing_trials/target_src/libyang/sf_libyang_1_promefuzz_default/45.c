// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_find_path at tree_data.c:3700:1 in tree_data.h
// lyd_dup_siblings at tree_data.c:2535:1 in tree_data.h
// lyd_eval_xpath3 at tree_data.c:3463:1 in tree_data.h
// lyd_change_meta at tree_data_new.c:1224:1 in tree_data.h
// lyd_trim_xpath at tree_data.c:3581:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libyang.h>
#include "tree_data.h"

static void fuzz_lyd_find_path(const uint8_t *Data, size_t Size) {
    struct lyd_node *ctx_node = NULL;
    char *path = strndup((const char *)Data, Size);
    ly_bool output = 0;
    struct lyd_node *match = NULL;

    if (path) {
        lyd_find_path(ctx_node, path, output, &match);
        free(path);
    }
}

static void fuzz_lyd_dup_siblings(const uint8_t *Data, size_t Size) {
    struct lyd_node *node = NULL;
    struct lyd_node *parent = NULL;
    uint32_t options = 0;
    struct lyd_node *dup = NULL;

    lyd_dup_siblings(node, parent, options, &dup);
}

static void fuzz_lyd_eval_xpath3(const uint8_t *Data, size_t Size) {
    struct lyd_node *ctx_node = NULL;
    struct lys_module *cur_mod = NULL;
    char *xpath = strndup((const char *)Data, Size);
    LY_VALUE_FORMAT format = 0;
    void *prefix_data = NULL;
    struct lyxp_var *vars = NULL;
    ly_bool result;

    if (xpath) {
        lyd_eval_xpath3(ctx_node, cur_mod, xpath, format, prefix_data, vars, &result);
        free(xpath);
    }
}

static void fuzz_lyd_change_meta(const uint8_t *Data, size_t Size) {
    struct lyd_meta *meta = NULL;
    char *val_str = strndup((const char *)Data, Size);

    if (val_str) {
        lyd_change_meta(meta, val_str);
        free(val_str);
    }
}

static void fuzz_lyd_trim_xpath(const uint8_t *Data, size_t Size) {
    struct lyd_node *tree = NULL;
    char *xpath = strndup((const char *)Data, Size);
    struct lyxp_var *vars = NULL;

    if (xpath) {
        lyd_trim_xpath(&tree, xpath, vars);
        free(xpath);
    }
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    struct lys_module *module = NULL;
    char *name = "dummy_name";
    char *value = (char *)malloc(Size + 1);
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (value) {
        memcpy(value, Data, Size);
        value[Size] = '\0';
        lyd_new_term(parent, module, name, value, options, &node);
        free(value);
    }
}

int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size) {
    fuzz_lyd_find_path(Data, Size);
    fuzz_lyd_dup_siblings(Data, Size);
    fuzz_lyd_eval_xpath3(Data, Size);
    fuzz_lyd_change_meta(Data, Size);
    fuzz_lyd_trim_xpath(Data, Size);
    fuzz_lyd_new_term(Data, Size);

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

        LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    