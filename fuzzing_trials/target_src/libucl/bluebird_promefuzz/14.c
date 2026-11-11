#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ucl.h"

static ucl_object_t* create_dummy_ucl_object(const char *key, const char *value) {
    ucl_object_t *obj = (ucl_object_t *)malloc(sizeof(ucl_object_t));
    if (obj) {
        obj->key = key;
        obj->value.sv = value;
        obj->keylen = key ? strlen(key) : 0;
    }
    return obj;
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 3) return 0; // Ensure there's enough data to split into strings

    // Split input data into two parts for keys and comments
    size_t key1_len = Data[0] % (Size - 2) + 1; // Ensure non-zero length
    size_t key2_len = Data[1] % (Size - key1_len - 1) + 1;
    size_t comment_len = Size - key1_len - key2_len - 2;

    if (key1_len + key2_len + 2 > Size || comment_len > Size) return 0; // Additional check to prevent overflow

    const char *key1 = (const char *)Data + 2;
    const char *key2 = (const char *)Data + 2 + key1_len;
    const char *comment = (const char *)Data + 2 + key1_len + key2_len;

    // Ensure null-termination of strings
    char *key1_str = strndup(key1, key1_len);
    char *key2_str = strndup(key2, key2_len);
    char *comment_str = strndup(comment, comment_len);

    if (!key1_str || !key2_str || !comment_str) goto cleanup;

    // Create dummy UCL objects
    ucl_object_t *obj1 = create_dummy_ucl_object(key1_str, "value1");
    ucl_object_t *obj2 = create_dummy_ucl_object(key2_str, "value2");
    ucl_object_t *comments = create_dummy_ucl_object(NULL, NULL);

    if (!obj1 || !obj2 || !comments) goto cleanup;

    // Test ucl_object_lookup
    (void)ucl_object_lookup(obj1, key1_str);
    (void)ucl_object_lookup(obj2, key2_str);

    // Test ucl_comments_add
    ucl_comments_add(comments, obj1, comment_str);

    // Test ucl_comments_find
    (void)ucl_comments_find(comments, obj1);
    (void)ucl_comments_find(comments, obj2);

    // Test ucl_comments_move
    (void)ucl_comments_move(comments, obj1, obj2);

cleanup:
    free(obj1);
    free(obj2);
    free(comments);
    free(key1_str);
    free(key2_str);
    free(comment_str);

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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
