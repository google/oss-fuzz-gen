#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int nc_get_var_chunk_cache(int ncid, int varid, size_t *sizep, size_t *nelemsp, float *preemptionp);

int LLVMFuzzerTestOneInput_67(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(float)) {
        return 0; // Not enough data to fill all parameters
    }

    // Extracting parameters from the data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));
    size_t sizep_val = *(const size_t *)(data + sizeof(int) * 2);
    size_t nelemsp_val = *(const size_t *)(data + sizeof(int) * 2 + sizeof(size_t));
    float preemptionp_val = *(const float *)(data + sizeof(int) * 2 + sizeof(size_t) * 2);

    // Initialize pointers
    size_t *sizep = &sizep_val;
    size_t *nelemsp = &nelemsp_val;
    float *preemptionp = &preemptionp_val;

    // Call the function-under-test
    nc_get_var_chunk_cache(ncid, varid, sizep, nelemsp, preemptionp);

    return 0;
}