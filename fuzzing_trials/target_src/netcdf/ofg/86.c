#include <stdint.h>
#include <stddef.h>

// Function-under-test declaration
int nc_set_var_chunk_cache(int varid, int cache_size, size_t cache_nelems, size_t cache_preemption, float cache_ratio);

int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract the necessary parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(float)) {
        return 0;
    }

    // Initialize parameters from the input data
    int varid = *((int*)data);
    int cache_size = *((int*)(data + sizeof(int)));
    size_t cache_nelems = *((size_t*)(data + 2 * sizeof(int)));
    size_t cache_preemption = *((size_t*)(data + 2 * sizeof(int) + sizeof(size_t)));
    float cache_ratio = *((float*)(data + 2 * sizeof(int) + 2 * sizeof(size_t)));

    // Call the function-under-test
    nc_set_var_chunk_cache(varid, cache_size, cache_nelems, cache_preemption, cache_ratio);

    return 0;
}