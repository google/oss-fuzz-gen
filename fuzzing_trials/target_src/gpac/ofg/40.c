#include <stdint.h>
#include <stdlib.h>
#include <stdio.h> // Include this to ensure FILE and remove are declared
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Use the input data to create a temporary file for fuzzing
    char filename[] = "/tmp/fuzz_input.mp4";
    FILE *tempFile = fopen(filename, "wb");
    if (!tempFile) {
        return 0;
    }
    fwrite(data, 1, size, tempFile);
    fclose(tempFile);

    // Open the temporary ISO file
    GF_ISOFile *movie = gf_isom_open(filename, GF_ISOM_OPEN_READ, NULL);
    if (!movie) {
        return 0;
    }

    u32 trackNumber = 1; // Initialize trackNumber to a valid value
    u32 StreamDescriptionIndex = 1; // Initialize StreamDescriptionIndex to a valid value
    Bool remove_flag = GF_FALSE; // Initialize remove_flag to a valid value

    // Call the function-under-test
    gf_isom_set_image_sequence_alpha(movie, trackNumber, StreamDescriptionIndex, remove_flag);

    gf_isom_close(movie); // Close the ISO file

    // Optionally, remove the temporary file
    remove(filename); // Use the standard remove function to delete the file

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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
