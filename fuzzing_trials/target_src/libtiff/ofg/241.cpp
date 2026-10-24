#include <tiffio.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h> // Include unistd.h for the close function

extern "C" {
    #include <tiffio.h> // Ensure all C headers are wrapped in extern "C"
}

extern "C" int LLVMFuzzerTestOneInput_241(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    if (fd == -1) {
        return 0;
    }

    FILE *file = fdopen(fd, "wb");
    if (file == nullptr) {
        close(fd);
        return 0;
    }

    if (fwrite(data, 1, size, file) != size) {
        fclose(file);
        return 0;
    }
    fclose(file);

    TIFF *tiff = TIFFOpen(tmpl, "r");
    if (tiff != nullptr) {
        // Call the function-under-test
        int result = TIFFIsBigEndian(tiff);
        // Optionally, you can use the result for further logic
        TIFFClose(tiff);
    }

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

    LLVMFuzzerTestOneInput_241(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
