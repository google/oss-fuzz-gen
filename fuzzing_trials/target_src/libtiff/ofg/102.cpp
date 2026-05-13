#include <cstdint>
#include <cstring>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for two non-empty buffers
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts
    size_t half_size = size / 2;
    const void *buf1 = static_cast<const void *>(data);

    // Create a separate buffer for buf2 to avoid modifying the const input data
    uint8_t *mutable_buf2 = new uint8_t[half_size];
    std::memcpy(mutable_buf2, data + half_size, half_size);

    // Define tmsize_t as the minimum of half_size and the maximum tmsize_t value
    tmsize_t len = static_cast<tmsize_t>(half_size);

    // Check if buffers are non-empty
    if (len == 0) {
        delete[] mutable_buf2;
        return 0;
    }

    // Ensure the buffers are not trivially equal
    if (std::memcmp(buf1, mutable_buf2, len) == 0) {
        // If they are equal, modify one buffer slightly to ensure they are different
        mutable_buf2[0] ^= 0xFF; // Flip the first byte
    }

    // Call the function-under-test
    int result = _TIFFmemcmp(buf1, mutable_buf2, len);

    // Use the result in some way to avoid compiler optimizations removing the call
    volatile int use_result = result;
    (void)use_result;

    // Clean up the allocated memory
    delete[] mutable_buf2;

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

    LLVMFuzzerTestOneInput_102(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
