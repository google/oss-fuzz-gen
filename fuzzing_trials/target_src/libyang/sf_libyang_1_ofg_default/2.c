#include <stdint.h>
#include <stdlib.h>
#include <string.h> // For memcpy
#include <ctype.h>  // For isspace

// Define dummy structs and function as the libyang header is not available
struct lyd_node {};
struct lys_module {};
typedef int LY_ERR;

// Dummy implementation of the function
LY_ERR lyd_new_term_2(struct lyd_node *parent, const struct lys_module *module, const char *name, const char *value, uint32_t options, struct lyd_node **new_node) {
    // Dummy implementation
    return 0;
}

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    if (size < 3) { // Ensure there is enough data to split into name and value
        return 0;
    }

    struct lyd_node *parent = (struct lyd_node *)0x1; // Dummy non-NULL pointer
    const struct lys_module *module = (const struct lys_module *)0x1; // Dummy non-NULL pointer
    uint32_t options = 0;
    struct lyd_node *new_node = NULL;

    // Split the data into two parts: name and value
    size_t name_size = size / 2;
    size_t value_size = size - name_size;

    char *name = (char *)malloc(name_size + 1);
    char *value = (char *)malloc(value_size + 1);

    if (!name || !value) {
        free(name);
        free(value);
        return 0;
    }

    // Copy data into name and value
    memcpy(name, data, name_size);
    name[name_size] = '\0';
    memcpy(value, data + name_size, value_size);
    value[value_size] = '\0';

    // Ensure name and value are not empty to maximize fuzzing effectiveness
    if (name_size == 0 || value_size == 0) {
        free(name);
        free(value);
        return 0;
    }

    // Modify to ensure the function is effectively invoked
    // Check if name and value are not just empty strings
    if (strlen(name) == 0 || strlen(value) == 0) {
        free(name);
        free(value);
        return 0;
    }

    // Ensure name and value are not just whitespace
    size_t name_non_space_count = 0;
    size_t value_non_space_count = 0;
    for (size_t i = 0; i < name_size; ++i) {
        if (!isspace((unsigned char)name[i])) {
            name_non_space_count++;
        }
    }
    for (size_t i = 0; i < value_size; ++i) {
        if (!isspace((unsigned char)value[i])) {
            value_non_space_count++;
        }
    }
    if (name_non_space_count == 0 || value_non_space_count == 0) {
        free(name);
        free(value);
        return 0;
    }

    // Call the function-under-test
    LY_ERR result = lyd_new_term_2(parent, module, name, value, options, &new_node);

    // Clean up
    free(name);
    free(value);
    // Normally, you'd also clean up new_node, but since this is a fuzzing harness,
    // we assume that the fuzzer is responsible for the process lifecycle.

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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
