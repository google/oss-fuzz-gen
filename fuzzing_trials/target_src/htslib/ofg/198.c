#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Assuming the function is declared in some header file
int hts_resize_array_(size_t, size_t, size_t, void *, void **, int, const char *);

int LLVMFuzzerTestOneInput_198(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract parameters
    if (size < sizeof(size_t) * 3 + sizeof(int) + 1) {
        return 0;
    }

    size_t param1, param2, param3;
    void *array = NULL;
    void *new_array = NULL;
    int param6;
    const char *param7;

    // Extract parameters from the input data
    memcpy(&param1, data, sizeof(size_t));
    memcpy(&param2, data + sizeof(size_t), sizeof(size_t));
    memcpy(&param3, data + 2 * sizeof(size_t), sizeof(size_t));
    memcpy(&param6, data + 3 * sizeof(size_t), sizeof(int));
    param7 = (const char *)(data + 3 * sizeof(size_t) + sizeof(int));

    // Ensure param7 is null-terminated within the bounds of the input data
    size_t max_param7_length = size - (3 * sizeof(size_t) + sizeof(int));
    char *param7_copy = strndup(param7, max_param7_length);
    if (!param7_copy) {
        return 0; // Return if memory allocation fails for param7_copy
    }

    // Allocate memory for the array based on extracted parameters
    if (param1 > 0 && param2 > 0 && param1 <= SIZE_MAX / param2) {
        array = malloc(param1 * param2);
        if (!array) {
            free(param7_copy); // Free the allocated memory for param7_copy
            return 0; // Return if memory allocation fails
        }
    } else {
        free(param7_copy); // Free the allocated memory for param7_copy
        return 0; // Return if parameters are not valid for allocation
    }

    // Call the function with the extracted parameters
    int result = hts_resize_array_(param1, param2, param3, array, &new_array, param6, param7_copy);

    // Check if new_array was modified and is not NULL
    if (result == 0 && new_array != NULL && new_array != array) {
        free(new_array); // Free the new_array if it was modified by hts_resize_array_
    }

    free(array); // Free the allocated memory
    free(param7_copy); // Free the allocated memory for param7_copy

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

    LLVMFuzzerTestOneInput_198(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
