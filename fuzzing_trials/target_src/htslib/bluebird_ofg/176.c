#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "htslib/hts.h"
#include "/src/htslib/htslib/thread_pool.h" // Include the header for thread pool functions

int LLVMFuzzerTestOneInput_176(const uint8_t *data, size_t size) {
    // Initialize htsFile and htsThreadPool
    htsFile *file = hts_open("-", "r");
    if (file == NULL) {
        return 0; // Exit if file initialization fails
    }

    htsThreadPool thread_pool;
    struct hts_tpool *pool = hts_tpool_init(2); // Initialize a thread pool with 2 threads
    if (pool == NULL) {
        hts_close(file);
        return 0; // Exit if thread pool initialization fails
    }

    thread_pool.pool = pool;
    thread_pool.qsize = 0; // Default queue size

    // Call the function-under-test
    int result = hts_set_thread_pool(file, &thread_pool);

    // Clean up
    hts_tpool_destroy(pool);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_176(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
