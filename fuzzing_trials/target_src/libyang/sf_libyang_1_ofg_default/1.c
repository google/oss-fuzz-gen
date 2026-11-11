#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Dummy declarations for the types and functions used
struct lyd_node {
    // Add necessary fields if needed
};

struct lys_module {
    // Add necessary fields if needed
};

typedef int LY_ERR;

// Dummy implementation of lyd_new_term_1
LY_ERR lyd_new_term_1(struct lyd_node *parent, const struct lys_module *module, const char *name, const char *value, uint32_t options, struct lyd_node **new_node) {
    // Dummy implementation
    return 0;
}

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    if (size < 2) { // Ensure we have enough data for meaningful name and value
        return 0;
    }

    // Create dummy parent and module objects
    struct lyd_node parent_dummy;
    struct lys_module module_dummy;

    struct lyd_node *parent = &parent_dummy;
    const struct lys_module *module = &module_dummy;
    uint32_t options = 0; // Using 0 as a default option
    struct lyd_node *new_node = NULL;

    // Split data into two parts for name and value
    size_t name_size = size / 2;
    size_t value_size = size - name_size;

    // Allocate memory for name and value
    char *name = (char *)malloc(name_size + 1);
    char *value = (char *)malloc(value_size + 1);

    if (name == NULL || value == NULL) {
        free(name);
        free(value);
        return 0;
    }

    // Ensure null-terminated strings
    memcpy(name, data, name_size);
    name[name_size] = '\0';
    memcpy(value, data + name_size, value_size);
    value[value_size] = '\0';

    // Call the function-under-test
    LY_ERR result = lyd_new_term_1(parent, module, name, value, options, &new_node);

    // Clean up
    free(name);
    free(value);

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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
