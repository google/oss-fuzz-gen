#include <stdint.h>
#include <stddef.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_167(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for creating non-NULL strings
    if (size < 2) {
        return 0;
    }

    // Initialize plist variables
    plist_t source_dict = plist_new_dict();
    plist_t dest_dict = plist_new_dict();

    // Create non-NULL strings for keys
    char key1[2] = { (char)data[0], '\0' };
    char key2[2] = { (char)data[1], '\0' };

    // Add a sample uint value to the source dictionary
    plist_dict_set_item(source_dict, key1, plist_new_uint(42));

    // Call the function-under-test
    plist_err_t result = plist_dict_copy_uint(dest_dict, source_dict, key1, key2);

    // Cleanup
    plist_free(source_dict);
    plist_free(dest_dict);

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

    LLVMFuzzerTestOneInput_167(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
