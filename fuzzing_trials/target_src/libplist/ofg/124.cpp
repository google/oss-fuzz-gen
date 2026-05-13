#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    plist_t node = NULL;

    // Create a plist node from the input data
    if (size > 0) {
        plist_from_bin((const char*)data, size, &node);
    }

    // Ensure the node is not NULL before calling the function-under-test
    if (node != NULL) {
        plist_type node_type = plist_get_node_type(node);

        // Optionally, you can perform additional operations based on node_type
        // For example, print or log the node type, etc.
    }

    // Free the plist node if it was created
    if (node != NULL) {
        plist_free(node);
    }

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

    LLVMFuzzerTestOneInput_124(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
