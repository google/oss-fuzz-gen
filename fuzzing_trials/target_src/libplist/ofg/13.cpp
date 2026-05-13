#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Ensure there's enough data to create two nodes
    }

    // Initialize plist nodes
    plist_t node1 = plist_new_string((const char *)data);
    plist_t node2 = plist_new_string((const char *)(data + 1));

    // Call the function-under-test
    char result = plist_compare_node_value(node1, node2);

    // Clean up
    plist_free(node1);
    plist_free(node2);

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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
