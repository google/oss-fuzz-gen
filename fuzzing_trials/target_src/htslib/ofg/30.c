#include <stdint.h>
#include <stddef.h>
#include <htslib/hts.h>
#include <htslib/thread_pool.h> // Include necessary library for thread pool

// Use the existing hts_fmt_option enum from htslib/hts.h
// No need to redefine DW_TAG_enumeration_typehts_fmt_option

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for our needs
    if (size < 2) { // Ensure we have at least two bytes of data
        return 0;
    }

    // Create a mock htsFile object
    htsFile *file = hts_open("-", "w"); // Open a file in write mode
    if (file == NULL) {
        return 0;
    }

    // Extract an option from the input data
    enum hts_fmt_option option = (enum hts_fmt_option)(data[0] % 3 + HTS_OPT_COMPRESSION_LEVEL);

    // Extract a value for the option from the input data
    int value = (int)data[1];

    // Prepare a dummy thread pool object for HTS_OPT_THREAD_POOL
    htsThreadPool thread_pool = { NULL, 0 }; // Initialize with default values

    // Create a real thread pool to avoid null pointer dereference
    hts_tpool *pool = hts_tpool_init(2); // Initialize a thread pool with 2 threads
    if (pool == NULL) {
        hts_close(file);
        return 0;
    }
    thread_pool.pool = pool;

    // Call the function-under-test
    // Ensure the option and value are valid to prevent undefined behavior
    if (option >= HTS_OPT_COMPRESSION_LEVEL && option <= HTS_OPT_THREAD_POOL) {
        if (option == HTS_OPT_THREAD_POOL) {
            hts_set_opt(file, option, &thread_pool); // Pass the thread pool for HTS_OPT_THREAD_POOL
        } else {
            hts_set_opt(file, option, (void *)&value);
        }
    }

    // Clean up
    hts_tpool_destroy(pool); // Destroy the thread pool
    hts_close(file);

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

    LLVMFuzzerTestOneInput_30(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
