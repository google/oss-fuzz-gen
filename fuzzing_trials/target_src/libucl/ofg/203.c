#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h> // Assuming the UCL library provides this header

int LLVMFuzzerTestOneInput_203(const uint8_t *data, size_t size) {
    // Initialize a ucl_object_t object
    ucl_object_t *obj = ucl_object_new_full(UCL_OBJECT, 0);
    
    // Create a size_t variable to hold the length of the key
    size_t key_length = 0;

    // If data is non-empty, try to parse it into the UCL object
    if (size > 0) {
        // Use the data to create a string and add it as a key to the object
        char *key = (char *)malloc(size + 1);
        if (key != NULL) {
            memcpy(key, data, size);
            key[size] = '\0'; // Null-terminate the string

            // Add the key to the UCL object
            ucl_object_insert_key(obj, ucl_object_fromstring("value"), key, size, true);
        }
    }

    // Call the function-under-test
    const char *key_str = ucl_object_keyl(obj, &key_length);

    // Clean up
    ucl_object_unref(obj);

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

    LLVMFuzzerTestOneInput_203(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
