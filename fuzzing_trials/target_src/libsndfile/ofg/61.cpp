#include <stddef.h>
#include <stdint.h>

// Assuming the definition of SF_CHUNK_ITERATOR and sf_next_chunk_iterator is available
extern "C" {
    typedef struct {
        int current_chunk;
        int total_chunks;
    } SF_CHUNK_ITERATOR;

    SF_CHUNK_ITERATOR* sf_next_chunk_iterator(SF_CHUNK_ITERATOR*);
}

extern "C" int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    // Initialize SF_CHUNK_ITERATOR with non-NULL values
    SF_CHUNK_ITERATOR iterator;
    iterator.current_chunk = 0;
    iterator.total_chunks = 10; // Example value, ensure this is non-zero

    // Call the function-under-test
    SF_CHUNK_ITERATOR* result = sf_next_chunk_iterator(&iterator);

    // Normally, we would perform some checks or use 'result', but for fuzzing, we just need to call the function
    (void)result; // Suppress unused variable warning

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

    LLVMFuzzerTestOneInput_61(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
