#include <stdint.h>
#include <stddef.h>

// Assuming the function gdbm_version_cmp is declared in a header file like this:
int gdbm_version_cmp(const int *, const int *);

int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create two integers
    if (size < 2 * sizeof(int)) {
        return 0;
    }

    // Initialize two integer pointers from the input data
    const int *version1 = (const int *)data;
    const int *version2 = (const int *)(data + sizeof(int));

    // Call the function-under-test
    int result = gdbm_version_cmp(version1, version2);

    // Use the result to avoid compiler optimizations (not strictly necessary)
    (void)result;

    return 0;
}