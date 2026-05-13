#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming NC_Dispatch is defined elsewhere
typedef struct {
    // Placeholder for actual structure members
    int dummy;
} NC_Dispatch;

// Function signature
int nc_inq_user_format(int, NC_Dispatch **, char *);

// Fuzzing harness
int LLVMFuzzerTestOneInput_497(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + sizeof(NC_Dispatch) + 1) {
        // Ensure there's enough data for an int, a pointer, and at least one char
        return 0;
    }

    // Extract an integer from the data
    int int_param = *(int *)data;

    // Allocate memory for NC_Dispatch and copy data into it
    NC_Dispatch *dispatch_param = (NC_Dispatch *)malloc(sizeof(NC_Dispatch));
    if (dispatch_param == NULL) {
        return 0;
    }
    memcpy(dispatch_param, data + sizeof(int), sizeof(NC_Dispatch));

    // Allocate memory for a string and copy remaining data into it
    size_t str_size = size - sizeof(int) - sizeof(NC_Dispatch);
    char *str_param = (char *)malloc(str_size + 1);
    if (str_param == NULL) {
        free(dispatch_param);
        return 0;
    }
    memcpy(str_param, data + sizeof(int) + sizeof(NC_Dispatch), str_size);
    str_param[str_size] = '\0';  // Null-terminate the string

    // Call the function-under-test
    nc_inq_user_format(int_param, &dispatch_param, str_param);

    // Clean up
    free(dispatch_param);
    free(str_param);

    return 0;
}