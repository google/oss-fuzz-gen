#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include this for memcpy

// Assuming necessary libyang headers are available in the include path
// Remove the incorrect include directive for libyang

// Declare the necessary libyang structures and functions
struct lyd_node;
struct lys_module;
typedef int LY_ERR;

extern LY_ERR lyd_new_term(struct lyd_node *parent, const struct lys_module *module,
                           const char *name, const char *value, uint32_t options,
                           struct lyd_node **new_node);
extern void lyd_free_tree(struct lyd_node *node);

// Remove 'extern "C"' as this is not valid in C, it's for C++ linkage
int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    struct lyd_node *parent = NULL;
    const struct lys_module *module = NULL;
    char *name = NULL;
    char *value = NULL;
    uint32_t options = 0;
    struct lyd_node *new_node = NULL;

    // Ensure that size is large enough to split into two strings
    if (size < 2) {
        return 0;
    }

    // Allocate memory for name and value, split data into two parts
    name = (char *)malloc(size / 2 + 1);
    value = (char *)malloc(size / 2 + 1);

    if (name == NULL || value == NULL) {
        free(name);
        free(value);
        return 0;
    }

    // Copy data into name and value
    memcpy(name, data, size / 2);
    name[size / 2] = '\0';
    memcpy(value, data + size / 2, size / 2);
    value[size / 2] = '\0';

    // Call the function-under-test
    LY_ERR result = lyd_new_term(parent, module, name, value, options, &new_node);

    // Clean up
    free(name);
    free(value);
    lyd_free_tree(new_node);

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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
