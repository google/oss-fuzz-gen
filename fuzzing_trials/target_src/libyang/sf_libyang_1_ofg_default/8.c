#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include string.h for memcpy

// Mock definitions for the purpose of compiling the fuzz harness
// These should match the expected signatures in the actual libyang library
struct lyd_node {};
struct lys_module {};

int lyd_new_term_8(struct lyd_node *parent, const struct lys_module *module, 
                 const char *name, const char *value, uint32_t options, 
                 struct lyd_node **new_node) {
    // Mock implementation of the function
    // In a real scenario, this would be linked against the actual library
    return 0;
}

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    if (size < 2) {
        // Ensure there is enough data to split into name and value
        return 0;
    }

    struct lyd_node *parent = (struct lyd_node *)0x1; // Non-NULL dummy pointer
    const struct lys_module *module = (const struct lys_module *)0x2; // Non-NULL dummy pointer
    uint32_t options = 0; // Default options
    struct lyd_node *new_node = NULL;

    // Split the input data into two parts: name and value
    size_t name_size = size / 2;
    size_t value_size = size - name_size;
    
    char *name = (char *)malloc(name_size + 1);
    char *value = (char *)malloc(value_size + 1);

    if (name == NULL || value == NULL) {
        free(name);
        free(value);
        return 0;
    }

    // Ensure null-termination
    memcpy(name, data, name_size);
    name[name_size] = '\0';
    memcpy(value, data + name_size, value_size);
    value[value_size] = '\0';

    // Call the function-under-test
    lyd_new_term_8(parent, module, name, value, options, &new_node);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
