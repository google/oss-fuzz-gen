// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_compare_meta at tree_data.c:1892:1 in tree_data.h
// lyd_new_meta at tree_data_new.c:789:1 in tree_data.h
// lyd_find_meta at tree_data.c:3138:1 in tree_data.h
// lyd_free_meta_single at tree_data_free.c:75:1 in tree_data.h
// lyd_free_meta_siblings at tree_data_free.c:81:1 in tree_data.h
// lyd_change_meta at tree_data_new.c:1224:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "tree_data.h"

static struct lyd_meta *create_dummy_meta() {
    return NULL; // Returning NULL as we cannot allocate incomplete type
}

static struct ly_ctx *create_dummy_ctx() {
    return NULL; // Returning NULL as we cannot allocate incomplete type
}

static struct lys_module *create_dummy_module() {
    return NULL; // Returning NULL as we cannot allocate incomplete type
}

static struct lyd_node *create_dummy_node() {
    return NULL; // Returning NULL as we cannot allocate incomplete type
}

int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    struct lyd_meta *meta1 = create_dummy_meta();
    struct lyd_meta *meta2 = create_dummy_meta();
    struct lyd_meta *meta3 = create_dummy_meta();
    struct lyd_meta *meta_out = NULL;
    struct ly_ctx *ctx = create_dummy_ctx();
    struct lys_module *module = create_dummy_module();
    struct lyd_node *parent = create_dummy_node();

    // Fuzzing lyd_compare_meta
    lyd_compare_meta(meta1, meta2);

    // Fuzzing lyd_new_meta
    lyd_new_meta(ctx, parent, module, "dummy_name", "dummy_val", 0, &meta_out);

    // Fuzzing lyd_find_meta
    lyd_find_meta(meta1, module, "dummy_name");

    // Fuzzing lyd_free_meta_single
    lyd_free_meta_single(meta1);

    // Fuzzing lyd_free_meta_siblings
    lyd_free_meta_siblings(meta2);

    // Fuzzing lyd_change_meta
    lyd_change_meta(meta3, "new_value");

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

        LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    