#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_163(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Ensure there is enough data to create at least one plist node
    }

    // Create two plist nodes
    plist_t node1 = plist_new_dict();
    plist_t node2 = plist_new_dict();

    // Populate the first plist node with some data
    plist_dict_set_item(node1, "key1", plist_new_string("value1"));
    plist_dict_set_item(node1, "key2", plist_new_uint(size));

    // Populate the second plist node with some data based on the input data
    plist_dict_set_item(node2, "key3", plist_new_data(reinterpret_cast<const char*>(data), size / 2));
    plist_dict_set_item(node2, "key4", plist_new_bool(data[0] % 2));

    // Call the function-under-test
    plist_dict_merge(&node1, node2);

    // Free the plist nodes
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

    LLVMFuzzerTestOneInput_163(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
