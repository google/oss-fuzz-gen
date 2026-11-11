#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming NC_Dispatch is a known struct type
typedef struct {
    // Add necessary fields if needed
} NC_Dispatch;

// Function-under-test declaration
int nc_inq_user_format(int, NC_Dispatch **, char *);

// Fuzzing harness
int LLVMFuzzerTestOneInput_496(const uint8_t *data, size_t size) {
    // Ensure that size is sufficient to extract meaningful data
    if (size < sizeof(int) + sizeof(NC_Dispatch *) + 1) {
        return 0;
    }

    // Extract an integer from the data
    int format = (int)data[0];

    // Allocate memory for NC_Dispatch and initialize it
    NC_Dispatch *dispatch = (NC_Dispatch *)malloc(sizeof(NC_Dispatch));
    if (dispatch == NULL) {
        return 0;
    }
    // Optionally initialize fields of dispatch if necessary

    // Create a buffer for the char* argument
    char *format_name = (char *)malloc(size - sizeof(int) - sizeof(NC_Dispatch *));
    if (format_name == NULL) {
        free(dispatch);
        return 0;
    }
    memcpy(format_name, data + sizeof(int) + sizeof(NC_Dispatch *), size - sizeof(int) - sizeof(NC_Dispatch *));

    // Call the function-under-test
    nc_inq_user_format(format, &dispatch, format_name);

    // Free allocated memory
    free(dispatch);
    free(format_name);

    return 0;
}