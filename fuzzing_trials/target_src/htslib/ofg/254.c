#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int hfile_list_plugins(const char **, int *);

int LLVMFuzzerTestOneInput_254(const uint8_t *data, size_t size) {
    // Ensure that size is sufficient to create at least one string and an integer
    if (size < 2) {
        return 0;
    }

    // Allocate memory for a single string
    char *plugin_name = (char *)malloc(size + 1);
    if (plugin_name == NULL) {
        return 0;
    }

    // Copy data into the string and null-terminate it
    memcpy(plugin_name, data, size);
    plugin_name[size] = '\0';

    // Create an array of string pointers
    const char *plugins[] = { plugin_name };

    // Initialize an integer
    int plugin_count = 0;

    // Call the function-under-test
    hfile_list_plugins(plugins, &plugin_count);

    // Free allocated memory
    free(plugin_name);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_254(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
