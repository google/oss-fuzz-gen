#include <stdlib.h>
#include "/src/libyang/src/tree_data.h"

int LLVMFuzzerTestOneInput_105(const uint8_t *data, size_t size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    const char *list_name = "example-list";
    const void **values = NULL;
    uint32_t *value_types = NULL;
    uint32_t value_count = 1;
    struct lyd_node *new_node = NULL;
    LY_ERR err;

    // Allocate memory for values and value_types
    values = (const void **)malloc(sizeof(void *) * value_count);
    value_types = (uint32_t *)malloc(sizeof(uint32_t) * value_count);

    if (values == NULL || value_types == NULL) {
        free(values);
        free(value_types);
        return 0;
    }

    // Initialize values and value_types with non-NULL values
    values[0] = (const void *)data;
    value_types[0] = LY_TYPE_STRING;

    // Call the function-under-test
    err = lyd_new_list3(parent, module, list_name, values, value_types, value_count, &new_node);

    // Free allocated memory
    free(values);
    free(value_types);

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

    LLVMFuzzerTestOneInput_105(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
