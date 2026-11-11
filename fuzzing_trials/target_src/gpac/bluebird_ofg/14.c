#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

// Define the function prototype for gf_isom_extract_meta_xml
GF_EXPORT int gf_isom_extract_meta_xml(GF_ISOFile *file, Bool root_meta, u32 track_num, char *outName, Bool *is_binary);

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Create a temporary file from the input data
    char temp_filename[] = "/tmp/fuzz_input_XXXXXX";
    int fd = mkstemp(temp_filename);
    if (fd == -1) {
        return 0; // Return if the temp file cannot be created
    }
    write(fd, data, size);
    close(fd);

    // Initialize the parameters for the function
    GF_ISOFile *file = gf_isom_open(temp_filename, GF_ISOM_OPEN_READ, NULL); // Open the ISO file from the temp file
    if (!file) {
        remove(temp_filename); // Clean up the temp file
        return 0; // Return if the file cannot be opened
    }

    Bool root_meta = (Bool)(data[0] % 2);  // Use the first byte to determine true/false
    u32 track_num = (u32)(data[1]);        // Use the second byte for track number
    char outName[256];                     // Output name buffer
    Bool is_binary;

    // Ensure outName is not NULL and has a valid string
    if (size >= 3) {
        snprintf(outName, sizeof(outName), "output_%u.xml", data[2]);
    } else {
        snprintf(outName, sizeof(outName), "output_default.xml");
    }

    // Call the function-under-test
    gf_isom_extract_meta_xml(file, root_meta, track_num, outName, &is_binary);

    // Close the ISO file after use
    gf_isom_close(file);

    // Clean up the temp file
    remove(temp_filename);

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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
