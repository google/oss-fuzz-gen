#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h> // Include the Little CMS library header

int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    // Initialize a cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL); // Properly create a context

    // Check if the context is created successfully
    if (context == NULL) {
        return 0; // Return if context creation failed
    }

    // Call the function-under-test
    cmsHANDLE handle = cmsDictAlloc(context);

    // Check if the handle is not NULL
    if (handle != NULL) {
        // Use the input data to create a key-value pair
        if (size > 1) {
            // Ensure there's enough data for a key and value
            size_t keyLen = data[0] % (size - 1) + 1; // Ensure keyLen is at least 1 and less than size
            size_t valueLen = size - keyLen;

            // Allocate memory for key and value
            wchar_t* key = (wchar_t*)malloc((keyLen + 1) * sizeof(wchar_t));
            wchar_t* value = (wchar_t*)malloc((valueLen + 1) * sizeof(wchar_t));

            if (key != NULL && value != NULL) {
                // Copy data into key and value
                mbstowcs(key, (const char*)(data + 1), keyLen);
                mbstowcs(value, (const char*)(data + 1 + keyLen), valueLen);

                // Null-terminate the strings
                key[keyLen] = L'\0';
                value[valueLen] = L'\0';

                // Add the key-value pair to the dictionary
                cmsDictAddEntry(handle, key, value, NULL, NULL);

                // Free allocated memory for key and value
                free(key);
                free(value);
            }
        }

        // Free the dictionary handle
        cmsDictFree(handle);
    }

    // Free the context
    cmsDeleteContext(context);

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

    LLVMFuzzerTestOneInput_152(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
