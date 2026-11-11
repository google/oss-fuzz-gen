#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>  // Include the plist library header

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create a valid string
    if (size < 1) {
        return 0;
    }

    // Create a plist node of type PLIST_STRING
    plist_t plist_node = plist_new_string("");

    // Allocate memory for the string, ensuring it is null-terminated
    char *string_val = (char *)malloc(size + 1);
    if (string_val == NULL) {
        plist_free(plist_node);
        return 0;
    }

    // Copy the data into the string and null-terminate it
    memcpy(string_val, data, size);
    string_val[size] = '\0';

    // Call the function-under-test
    plist_set_string_val(plist_node, string_val);

    // Clean up
    free(string_val);
    plist_free(plist_node);

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
