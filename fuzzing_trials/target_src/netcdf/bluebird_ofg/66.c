#include <stddef.h>
#include <stdint.h>

// Function signature for the function-under-test
int nc_set_var_chunk_cache(int ncid, int varid, size_t size, size_t nelems, float preemption);

int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for our parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(float)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));
    size_t cache_size = *(const size_t *)(data + sizeof(int) * 2);
    size_t nelems = *(const size_t *)(data + sizeof(int) * 2 + sizeof(size_t));
    float preemption = *(const float *)(data + sizeof(int) * 2 + sizeof(size_t) * 2);

    // Call the function-under-test
    nc_set_var_chunk_cache(ncid, varid, cache_size, nelems, preemption);

    return 0;
}