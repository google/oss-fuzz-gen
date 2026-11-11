#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/htslib/htslib/hfile.h" // Correct path for hFILE

int LLVMFuzzerTestOneInput_228(const uint8_t *data, size_t size) {
    // Initialize parameters for hgetdelim
    char *buffer;
    size_t buffer_size;
    int delimiter;
    hFILE *file;

    // Ensure the size is sufficient for testing
    if (size < 2) {
        return 0;
    }

    // Allocate buffer and copy data into it
    buffer_size = size;
    buffer = (char *)malloc(buffer_size);
    if (buffer == NULL) {
        return 0;
    }
    memcpy(buffer, data, size);

    // Set a delimiter from the data
    delimiter = data[size - 1];

    // Create a temporary file and write data to it
    FILE *temp_file = tmpfile();
    if (temp_file == NULL) {
        free(buffer);
        return 0;
    }
    fwrite(data, 1, size, temp_file);
    rewind(temp_file);

    // Open the temporary file as an hFILE
    file = hopen(temp_file, "r");
    if (file == NULL) {
        fclose(temp_file);
        free(buffer);
        return 0;
    }

    // Call the function-under-test
    ssize_t result = hgetdelim(buffer, buffer_size, delimiter, file);

    // Clean up
    hclose(file);
    fclose(temp_file);
    free(buffer);

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

    LLVMFuzzerTestOneInput_228(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
