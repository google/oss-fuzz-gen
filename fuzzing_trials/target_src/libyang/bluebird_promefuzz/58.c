#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libyang/src/parser_data.h"
#include "/src/libyang/src/tree_data.h"

static void fuzz_lyd_new_list2(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    char *name = NULL;
    char *keys = NULL;
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (Size < 4) {
        return;
    }

    name = strndup((const char *)Data, Size / 2);
    keys = strndup((const char *)(Data + Size / 2), Size / 2);

    lyd_new_list2(parent, module, name, keys, options, &node);

    free(name);
    free(keys);
    lyd_free_all(node);
}

static void fuzz_lyd_validate_op(const uint8_t *Data, size_t Size) {
    struct lyd_node *op_tree = NULL;
    const struct lyd_node *dep_tree = NULL;
    enum lyd_type data_type = LYD_TYPE_DATA_YANG;
    struct lyd_node *diff = NULL;

    lyd_validate_op(op_tree, dep_tree, data_type, &diff);

    lyd_free_all(op_tree);
    lyd_free_all(diff);
}

static void fuzz_lyd_list_pos(const uint8_t *Data, size_t Size) {
    struct lyd_node *instance = NULL;
    uint32_t pos = lyd_list_pos(instance);

    (void)pos;
}

static void fuzz_lyd_merge_tree(const uint8_t *Data, size_t Size) {
    struct lyd_node *target = NULL;
    const struct lyd_node *source = NULL;
    uint16_t options = 0;

    lyd_merge_tree(&target, source, options);

    lyd_free_all(target);
}

static void fuzz_lyd_child_no_keys(const uint8_t *Data, size_t Size) {
    struct lyd_node *node = NULL;
    struct lyd_node *child = lyd_child_no_keys(node);

    (void)child;
}

static void fuzz_lyd_is_default(const uint8_t *Data, size_t Size) {
    struct lyd_node *node = NULL;

    // Check if the node is not NULL before calling lyd_is_default
    if (node) {
        ly_bool is_default = lyd_is_default(node);
        (void)is_default;
    }
}

int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size) {
    fuzz_lyd_new_list2(Data, Size);
    fuzz_lyd_validate_op(Data, Size);
    fuzz_lyd_list_pos(Data, Size);
    fuzz_lyd_merge_tree(Data, Size);
    fuzz_lyd_child_no_keys(Data, Size);
    fuzz_lyd_is_default(Data, Size);

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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
