#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int hfile_list_plugins(const char **, int *);

int LLVMFuzzerTestOneInput_255(const uint8_t *data, size_t size) {
    // Ensure that we have enough data to work with
    if (size < 2) {
        return 0;
    }

    // Allocate memory for the plugin names array
    const char *plugin_names[2] = {NULL, NULL};

    // Allocate memory for the plugin count
    int plugin_count = 0;

    // Create a temporary buffer for plugin name
    char plugin_name[256];
    size_t name_length = size < 255 ? size : 255;
    for (size_t i = 0; i < name_length; i++) {
        plugin_name[i] = (char)data[i];
    }
    plugin_name[name_length] = '\0';

    // Assign the plugin name to the array
    plugin_names[0] = plugin_name;

    // Call the function-under-test
    hfile_list_plugins(plugin_names, &plugin_count);

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

    LLVMFuzzerTestOneInput_255(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
