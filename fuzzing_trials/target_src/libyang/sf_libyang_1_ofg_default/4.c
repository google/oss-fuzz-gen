#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>  // Include string.h for memcpy

// Forward declare the function to avoid dependency on unavailable headers
struct lyd_node;
struct lys_module;
int lyd_new_term(struct lyd_node *parent, const struct lys_module *module, const char *name, const char *value, uint32_t options, struct lyd_node **new_node);

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    struct lyd_node *parent = (struct lyd_node *)0x1;  // Non-NULL dummy pointer
    const struct lys_module *module = (const struct lys_module *)0x1;  // Non-NULL dummy pointer
    char *name = (char *)malloc(size + 1);
    char *value = (char *)malloc(size + 1);
    uint32_t options = 0;
    struct lyd_node *new_node = NULL;

    if (name == NULL || value == NULL) {
        free(name);
        free(value);
        return 0;
    }

    // Copy data to name and value, ensuring they are null-terminated
    if (size > 0) {
        memcpy(name, data, size);
        name[size] = '\0';
        memcpy(value, data, size);
        value[size] = '\0';
    } else {
        name[0] = '\0';
        value[0] = '\0';
    }

    // Call the function-under-test
    lyd_new_term(parent, module, name, value, options, &new_node);

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
