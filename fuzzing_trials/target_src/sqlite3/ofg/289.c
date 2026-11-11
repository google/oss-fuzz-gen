#include <stddef.h>  // Include this to define size_t
#include <stdint.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_289(const uint8_t *data, size_t size) {
    // Call the function-under-test
    sqlite3_int64 memoryUsed = sqlite3_memory_used();

    // Use the returned value in some way to avoid compiler optimizations removing the call
    if (memoryUsed > 0) {
        // Do something trivial with memoryUsed, such as printing or storing it
        volatile sqlite3_int64 temp = memoryUsed; // Prevent optimization
    }

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

    LLVMFuzzerTestOneInput_289(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
