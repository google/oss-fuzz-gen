#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "htslib/hfile.h"

// This function is used to test the hfile_mem_steal_buffer function
int LLVMFuzzerTestOneInput_159(const uint8_t *data, size_t size) {
    // Create a memory buffer and initialize an hFILE object with it
    hFILE *file = hopen("mem:", "w+");
    if (file == NULL) {
        return 0; // If the file cannot be opened, exit early
    }

    // Write the input data to the hFILE object
    if (hwrite(file, data, size) != size) {
        hclose(file);
        return 0; // If the data cannot be written, exit early
    }

    // Initialize a size_t variable to hold the size of the buffer
    size_t buffer_size = 0;

    // Call the function-under-test
    char *buffer = hfile_mem_steal_buffer(file, &buffer_size);

    // Clean up
    if (buffer != NULL) {
        free(buffer); // Free the buffer if it was successfully stolen
    }
    hclose(file); // Close the hFILE object

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

    LLVMFuzzerTestOneInput_159(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
