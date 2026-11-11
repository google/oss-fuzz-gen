#include <tiffio.h>
#include <cstdint>
#include <cstdlib>
#include <cstdio>

// Define a custom TIFF read function
tsize_t customRead(thandle_t fd, tdata_t buf, tsize_t size) {
    return fread(buf, 1, size, (FILE *)fd);
}

// Define a custom TIFF write function
tsize_t customWrite(thandle_t fd, tdata_t buf, tsize_t size) {
    return fwrite(buf, 1, size, (FILE *)fd);
}

// Define a custom TIFF seek function
toff_t customSeek(thandle_t fd, toff_t off, int whence) {
    return fseek((FILE *)fd, off, whence);
}

// Define a custom TIFF close function
int customClose(thandle_t fd) {
    return fclose((FILE *)fd);
}

// Define a custom TIFF size function
toff_t customSize(thandle_t fd) {
    fseek((FILE *)fd, 0, SEEK_END);
    return ftell((FILE *)fd);
}

// Define a custom TIFF map file function
int customMap(thandle_t fd, tdata_t *pbase, toff_t *psize) {
    return 0;
}

// Define a custom TIFF unmap file function
void customUnmap(thandle_t fd, tdata_t base, toff_t size) {
    // No operation
}

extern "C" int LLVMFuzzerTestOneInput_185(const uint8_t *data, size_t size) {
    // Create a temporary file to hold the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    FILE *file = fdopen(fd, "wb+");
    if (file == nullptr) {
        return 0;
    }

    // Write the fuzzing data to the file
    fwrite(data, 1, size, file);
    rewind(file);

    // Open a TIFF client using custom I/O functions
    TIFF *tiff = TIFFClientOpen("fuzz.tiff", "r", (thandle_t)file,
                                customRead, customWrite, customSeek, customClose,
                                customSize, customMap, customUnmap);
    if (tiff == nullptr) {
        fclose(file);
        return 0;
    }

    // Call the function-under-test
    thandle_t clientData = TIFFClientdata(tiff);

    // Clean up
    TIFFClose(tiff);
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_185(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
