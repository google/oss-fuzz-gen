#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libyang.h"
#include "/src/libyang/src/parser_data.h"
#include "/src/libyang/src/tree_data.h"

#define DUMMY_FILE_PATH "./dummy_file"

static void test_ly_pattern_match(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    char *pattern = NULL;
    char *string = NULL;
    uint32_t str_len = 0;
    void *pat_comp = NULL;

    if (Size < 2) {
        return;
    }

    pattern = (char *)malloc(Size / 2 + 1);
    string = (char *)malloc(Size / 2 + 1);
    if (!pattern || !string) {
        free(pattern);
        free(string);
        return;
    }

    memcpy(pattern, Data, Size / 2);
    pattern[Size / 2] = '\0';
    memcpy(string, Data + Size / 2, Size / 2);
    string[Size / 2] = '\0';
    str_len = Size / 2;

    ly_ctx_new(NULL, 0, &ctx);

    ly_pattern_match(ctx, pattern, string, str_len, &pat_comp);

    if (pat_comp) {
        ly_pattern_free(pat_comp);
    }

    free(pattern);
    free(string);
    ly_ctx_destroy(ctx);
}

static void test_ly_pattern_compile(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    char *pattern = NULL;
    void *pat_comp = NULL;

    if (Size == 0) {
        return;
    }

    pattern = (char *)malloc(Size + 1);
    if (!pattern) {
        return;
    }
    memcpy(pattern, Data, Size);
    pattern[Size] = '\0';

    ly_ctx_new(NULL, 0, &ctx);

    ly_pattern_compile(ctx, pattern, &pat_comp);

    if (pat_comp) {
        ly_pattern_free(pat_comp);
    }

    free(pattern);
    ly_ctx_destroy(ctx);
}

static void test_lyd_change_term(const uint8_t *Data, size_t Size) {
    struct lyd_node *term = NULL;
    const char *val_str = (const char *)Data;

    if (Size == 0) {
        return;
    }

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function lyd_change_term with lyd_change_term_canon
    lyd_change_term_canon(term, val_str);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
}

static void test_lyd_parse_data_path(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL;
    FILE *f = NULL;

    if (Size == 0) {
        return;
    }

    f = fopen(DUMMY_FILE_PATH, "wb");
    if (!f) {
        return;
    }
    fwrite(Data, 1, Size, f);
    fclose(f);

    ly_ctx_new(NULL, 0, &ctx);

    lyd_parse_data_path(ctx, DUMMY_FILE_PATH, 0, 0, 0, &tree);

    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
}

static void test_lyd_value_validate(const uint8_t *Data, size_t Size) {
    const struct lysc_node *schema = NULL;
    const char *value = (const char *)Data;
    uint32_t value_len = Size;
    const struct lyd_node *ctx_node = NULL;
    const struct lysc_type *realtype = NULL;
    const char *canonical = NULL;

    if (Size == 0) {
        return;
    }

    lyd_value_validate(schema, value, value_len, ctx_node, &realtype, &canonical);

    if (canonical) {
        lydict_remove(NULL, canonical);
    }
}

int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size) {
    test_ly_pattern_match(Data, Size);
    test_ly_pattern_compile(Data, Size);
    test_lyd_change_term(Data, Size);
    test_lyd_parse_data_path(Data, Size);
    test_lyd_value_validate(Data, Size);

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

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
