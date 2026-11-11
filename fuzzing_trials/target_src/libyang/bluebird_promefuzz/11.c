#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libyang/src/tree_data.h"
#include "libyang.h"

static struct lys_module dummy_module = {0};
static struct ly_ctx *dummy_ctx = NULL;

static void prepare_dummy_environment() {
    if (!dummy_ctx) {
        ly_ctx_new(NULL, 0, &dummy_ctx);
    }
    dummy_module.ctx = dummy_ctx;
    dummy_module.name = "dummy_module";
}

static void fuzz_lyd_new_list3(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = &dummy_module;
    const char *name = "list_node";
    const void **key_values = NULL;
    uint32_t *value_sizes_bits = NULL;
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (Size < sizeof(uint32_t)) return;

    // Use some of the input data as options
    options = *((uint32_t *)Data);
    Data += sizeof(uint32_t);
    Size -= sizeof(uint32_t);

    // Call the function with the prepared data
    lyd_new_list3(parent, module, name, key_values, value_sizes_bits, options, &node);

    // Clean up if node was created
    if (node) {
        lyd_free_tree(node);
    }
}

static void fuzz_lyd_new_inner(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = &dummy_module;
    const char *name = "inner_node";
    ly_bool output = 0;
    struct lyd_node *node = NULL;

    if (Size < sizeof(ly_bool)) return;

    // Use some of the input data as output flag
    output = *((ly_bool *)Data);
    Data += sizeof(ly_bool);
    Size -= sizeof(ly_bool);

    // Call the function with the prepared data
    lyd_new_inner(parent, module, name, output, &node);

    // Clean up if node was created
    if (node) {
        lyd_free_tree(node);
    }
}

static void fuzz_lyd_new_list(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = &dummy_module;
    const char *name = "list_node";
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (Size < sizeof(uint32_t)) return;

    // Use some of the input data as options
    options = *((uint32_t *)Data);
    Data += sizeof(uint32_t);
    Size -= sizeof(uint32_t);

    // Call the function with the prepared data
    lyd_new_list(parent, module, name, options, &node);

    // Clean up if node was created
    if (node) {
        lyd_free_tree(node);
    }
}

static void fuzz_lyd_new_path(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct ly_ctx *ctx = dummy_ctx;
    const char *path = "/dummy:path";
    const char *value = NULL;
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (Size < sizeof(uint32_t)) return;

    // Use some of the input data as options
    options = *((uint32_t *)Data);
    Data += sizeof(uint32_t);
    Size -= sizeof(uint32_t);

    // Use remaining data as value
    if (Size > 0) {
        value = (const char *)Data;
    }

    // Ensure value is null-terminated
    char *value_copy = NULL;
    if (value) {
        size_t value_len = strnlen(value, Size);
        value_copy = (char *)malloc(value_len + 1);
        if (value_copy) {
            memcpy(value_copy, value, value_len);
            value_copy[value_len] = '\0';
            value = value_copy;
        }
    }

    // Call the function with the prepared data
    lyd_new_path(parent, ctx, path, value, options, &node);

    // Clean up if node was created
    if (node) {
        lyd_free_tree(node);
    }

    // Free allocated memory
    free(value_copy);
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = &dummy_module;
    const char *name = "term_node";
    const char *value = NULL;
    uint32_t options = 0;
    struct lyd_node *node = NULL;

    if (Size < sizeof(uint32_t)) return;

    // Use some of the input data as options
    options = *((uint32_t *)Data);
    Data += sizeof(uint32_t);
    Size -= sizeof(uint32_t);

    // Use remaining data as value
    if (Size > 0) {
        value = (const char *)Data;
    }

    // Ensure value is null-terminated
    char *value_copy = NULL;
    if (value) {
        size_t value_len = strnlen(value, Size);
        value_copy = (char *)malloc(value_len + 1);
        if (value_copy) {
            memcpy(value_copy, value, value_len);
            value_copy[value_len] = '\0';
            value = value_copy;
        }
    }

    // Call the function with the prepared data
    lyd_new_term(parent, module, name, value, options, &node);

    // Clean up if node was created
    if (node) {
        lyd_free_tree(node);
    }

    // Free allocated memory
    free(value_copy);
}

static void fuzz_lyd_new_opaq(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    const struct ly_ctx *ctx = dummy_ctx;
    const char *name = "opaq_node";
    const char *value = NULL;
    const char *prefix = NULL;
    const char *module_name = "dummy_module";
    struct lyd_node *node = NULL;

    if (Size < 1) return;

    // Ensure there's enough data for a null-terminated string
    size_t prefix_len = strnlen((const char *)Data, Size);
    if (prefix_len < Size) {
        prefix = (const char *)Data;
        Data += prefix_len + 1;
        Size -= prefix_len + 1;
    }

    // Use remaining data as value
    if (Size > 0) {
        value = (const char *)Data;
    }

    // Ensure value is null-terminated
    char *value_copy = NULL;
    if (value) {
        size_t value_len = strnlen(value, Size);
        value_copy = (char *)malloc(value_len + 1);
        if (value_copy) {
            memcpy(value_copy, value, value_len);
            value_copy[value_len] = '\0';
            value = value_copy;
        }
    }

    // Call the function with the prepared data
    lyd_new_opaq(parent, ctx, name, value, prefix, module_name, &node);

    // Clean up if node was created
    if (node) {
        lyd_free_tree(node);
    }

    // Free allocated memory
    free(value_copy);
}

int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    prepare_dummy_environment();
    fuzz_lyd_new_list3(Data, Size);
    fuzz_lyd_new_inner(Data, Size);
    fuzz_lyd_new_list(Data, Size);
    fuzz_lyd_new_path(Data, Size);
    fuzz_lyd_new_term(Data, Size);
    fuzz_lyd_new_opaq(Data, Size);
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
