// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_change_term_canon at tree_data_new.c:1216:1 in tree_data.h
// lyd_change_term at tree_data_new.c:1208:1 in tree_data.h
// lyd_value_validate_dflt at tree_data_common.c:611:1 in tree_data.h
// lyd_value_validate at tree_data_common.c:601:1 in tree_data.h
// lyd_value_compare at tree_data_common.c:685:1 in tree_data.h
// ly_pattern_match at tree_data_common.c:1697:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tree_data.h"

static struct lyd_node *create_dummy_node() {
    struct lyd_node *node = malloc(sizeof(struct lyd_node));
    if (!node) {
        return NULL;
    }
    memset(node, 0, sizeof(struct lyd_node));
    return node;
}

static void free_dummy_node(struct lyd_node *node) {
    if (node) {
        free(node);
    }
}

static struct lysc_node *create_dummy_schema_node() {
    struct lysc_node *schema_node = malloc(sizeof(struct lysc_node));
    if (!schema_node) {
        return NULL;
    }
    memset(schema_node, 0, sizeof(struct lysc_node));
    return schema_node;
}

static void free_dummy_schema_node(struct lysc_node *schema_node) {
    if (schema_node) {
        free(schema_node);
    }
}

int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a null-terminated copy of the input data
    char *null_terminated_data = malloc(Size + 1);
    if (!null_terminated_data) {
        return 0;
    }
    memcpy(null_terminated_data, Data, Size);
    null_terminated_data[Size] = '\0';

    // ly_pattern_match
    {
        const struct ly_ctx *ctx = NULL;
        const char *pattern = null_terminated_data;
        const char *string = null_terminated_data;
        uint32_t str_len = Size;
        void *pat_comp = NULL;

        LY_ERR result = ly_pattern_match(ctx, pattern, string, str_len, &pat_comp);
        if (result == LY_SUCCESS || result == LY_ENOT || result == LY_EINVAL) {
            if (pat_comp) {
                ly_pattern_free(pat_comp);
            }
        }
    }

    // lyd_change_term_canon
    {
        struct lyd_node *term = create_dummy_node();
        if (term) {
            const char *val_str = null_terminated_data;

            LY_ERR result = lyd_change_term_canon(term, val_str);
            if (result == LY_SUCCESS || result == LY_EEXIST || result == LY_ENOT || result == LY_EINVAL) {
                // Handle result if needed
            }

            free_dummy_node(term);
        }
    }

    // lyd_value_validate_dflt
    {
        struct lysc_node *schema = create_dummy_schema_node();
        if (schema) {
            const char *value = null_terminated_data;
            struct lysc_prefix *prefixes = NULL;
            const struct lyd_node *ctx_node = NULL;
            const struct lysc_type **realtype = NULL;
            const char **canonical = NULL;

            LY_ERR result = lyd_value_validate_dflt(schema, value, prefixes, ctx_node, realtype, canonical);
            if (result == LY_SUCCESS || result == LY_EINCOMPLETE || result == LY_EINVAL) {
                // Handle result if needed
            }

            free_dummy_schema_node(schema);
        }
    }

    // lyd_value_compare
    {
        struct lyd_node_term *node = (struct lyd_node_term *)create_dummy_node();
        if (node) {
            const char *value = null_terminated_data;
            uint32_t value_len = Size;

            LY_ERR result = lyd_value_compare(node, value, value_len);
            if (result == LY_SUCCESS || result == LY_ENOT || result == LY_EINVAL) {
                // Handle result if needed
            }

            free_dummy_node((struct lyd_node *)node);
        }
    }

    // lyd_change_term
    {
        struct lyd_node *term = create_dummy_node();
        if (term) {
            const char *val_str = null_terminated_data;

            LY_ERR result = lyd_change_term(term, val_str);
            if (result == LY_SUCCESS || result == LY_EEXIST || result == LY_ENOT || result == LY_EINVAL) {
                // Handle result if needed
            }

            free_dummy_node(term);
        }
    }

    // lyd_value_validate
    {
        struct lysc_node *schema = create_dummy_schema_node();
        if (schema) {
            const char *value = null_terminated_data;
            uint32_t value_len = Size;
            const struct lyd_node *ctx_node = NULL;
            const struct lysc_type **realtype = NULL;
            const char **canonical = NULL;

            LY_ERR result = lyd_value_validate(schema, value, value_len, ctx_node, realtype, canonical);
            if (result == LY_SUCCESS || result == LY_EINCOMPLETE || result == LY_EINVAL) {
                // Handle result if needed
            }

            free_dummy_schema_node(schema);
        }
    }

    free(null_terminated_data);
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
    