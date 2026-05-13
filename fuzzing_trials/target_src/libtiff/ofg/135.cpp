#include <cstdint>
#include <cstdlib>
#include <unistd.h> // For close()
#include <algorithm> // For std::min
#include <cstdio> // For remove()
#include <cstring> // For memcpy

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    if (size < sizeof(uint32_t) + sizeof(tmsize_t)) {
        return 0;
    }

    // Create a temporary TIFF file
    char tmpl[] = "/tmp/fuzzfileXXXXXX.tiff";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Open the TIFF file for writing
    TIFF *tiff = TIFFOpen(tmpl, "w");
    if (tiff == nullptr) {
        remove(tmpl);
        return 0;
    }

    // Set up the TIFF file for tile writing using input data
    uint32_t width = *(reinterpret_cast<const uint32_t *>(data)) % 1024 + 1; // Ensure width is at least 1
    uint32_t length = *(reinterpret_cast<const uint32_t *>(data + 4)) % 1024 + 1; // Ensure length is at least 1
    TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, length);
    TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tiff, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tiff, TIFFTAG_ROWSPERSTRIP, length);
    TIFFSetField(tiff, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
    TIFFSetField(tiff, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
    TIFFSetField(tiff, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);

    // Calculate the number of tiles and ensure valid tile index
    uint32_t numTiles = TIFFNumberOfTiles(tiff);
    if (numTiles == 0) {
        TIFFClose(tiff);
        remove(tmpl);
        return 0;
    }

    // Extract the tile index and data size from the input
    uint32_t tileIndex = *(reinterpret_cast<const uint32_t *>(data + 8)) % numTiles;
    tmsize_t dataSize = *(reinterpret_cast<const tmsize_t *>(data + 12));

    // Ensure dataSize does not exceed the remaining input size
    dataSize = std::min(dataSize, static_cast<tmsize_t>(size - 16));

    // Prepare the tile data
    uint8_t *tileData = new uint8_t[dataSize];
    memcpy(tileData, data + 16, dataSize);

    // Call the function under test
    if (dataSize > 0) {
        // Ensure that the dataSize does not exceed the tile size
        tmsize_t tileSize = TIFFTileSize(tiff);
        dataSize = std::min(dataSize, tileSize);

        // Write the tile data
        TIFFWriteEncodedTile(tiff, tileIndex, tileData, dataSize);
    }

    // Clean up
    delete[] tileData;
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

    LLVMFuzzerTestOneInput_135(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
