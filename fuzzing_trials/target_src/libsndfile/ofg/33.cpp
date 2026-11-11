#include <cstdint>
#include <cstddef>
#include <cstring>

// Assuming these are the structures defined in the library for SF_CHUNK_ITERATOR and SF_CHUNK_INFO
typedef struct {
    // Add relevant fields here
    int dummy_field; // Example field
} SF_CHUNK_ITERATOR;

typedef struct {
    // Add relevant fields here
    int dummy_field; // Example field
} SF_CHUNK_INFO;

// Function signature from the task
extern "C" int sf_get_chunk_data(const SF_CHUNK_ITERATOR *, SF_CHUNK_INFO *);

// Fuzzing harness
extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to fill the structures
    if (size < sizeof(SF_CHUNK_ITERATOR) + sizeof(SF_CHUNK_INFO)) {
        return 0;
    }

    // Initialize SF_CHUNK_ITERATOR
    SF_CHUNK_ITERATOR chunk_iterator;
    std::memcpy(&chunk_iterator, data, sizeof(SF_CHUNK_ITERATOR));

    // Initialize SF_CHUNK_INFO
    SF_CHUNK_INFO chunk_info;
    std::memcpy(&chunk_info, data + sizeof(SF_CHUNK_ITERATOR), sizeof(SF_CHUNK_INFO));

    // Call the function-under-test
    sf_get_chunk_data(&chunk_iterator, &chunk_info);

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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
