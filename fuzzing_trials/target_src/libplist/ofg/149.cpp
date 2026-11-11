#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_149(const uint8_t *data, size_t size) {
    // Create a plist dictionary
    plist_t dict = plist_new_dict();
    
    // Check if size is sufficient to create a key
    if (size > 1) {
        // Use the first byte as the length of the key string
        size_t key_length = data[0] % (size - 1) + 1;
        
        // Allocate memory for the key string
        char *key = (char *)malloc(key_length + 1);
        
        // Copy key_length bytes from data to key
        memcpy(key, data + 1, key_length);
        
        // Null-terminate the key string
        key[key_length] = '\0';
        
        // Add an integer entry to the dictionary with the key
        plist_dict_set_item(dict, key, plist_new_int(42));
        
        // Call the function-under-test
        int64_t result = plist_dict_get_int(dict, key);
        
        // Free the allocated key
        free(key);
    }
    
    // Free the plist dictionary
    plist_free(dict);
    
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

    LLVMFuzzerTestOneInput_149(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
