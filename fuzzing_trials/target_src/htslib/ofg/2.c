#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/htslib/htslib/hfile.h"  // Correct path for hfile.h

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Ensure that the size is not zero
    if (size == 0) {
        return 0;
    }

    // Create a temporary file to use with hFILE
    char tmp_filename[L_tmpnam];
    if (tmpnam(tmp_filename) == NULL) {
        return 0;
    }

    FILE *temp_file = fopen(tmp_filename, "wb+");
    if (temp_file == NULL) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    fwrite(data, 1, size, temp_file);
    fflush(temp_file);

    // Rewind the file to the beginning for reading
    rewind(temp_file);
    fclose(temp_file);

    // Open the temporary file as an hFILE
    hFILE *hfile = hopen(tmp_filename, "w+"); // Open in write mode
    if (hfile == NULL) {
        remove(tmp_filename);
        return 0;
    }

    // Write the fuzz data to the hFILE
    hwrite(hfile, data, size);

    // Call the function-under-test
    int result = hflush(hfile);

    // Clean up
    hclose(hfile);
    remove(tmp_filename);

    return result;
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

    LLVMFuzzerTestOneInput_2(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
