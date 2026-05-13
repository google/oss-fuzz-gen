#include <tiffio.h>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <unistd.h> // Include this header for the 'close' function

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_136(const uint8_t *data, size_t size) {
    if (size < 8) { // Ensure there's enough data for meaningful processing
        return 0;
    }

    TIFF *tiff;
    uint32_t tileIndex = 0;
    tmsize_t bufferSize = static_cast<tmsize_t>(size);

    // Create a temporary TIFF file
    char tmpl[] = "/tmp/fuzzfileXXXXXX.tiff";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Open the TIFF file
    tiff = TIFFOpen(tmpl, "w");
    if (tiff == nullptr) {
        return 0;
    }

    // Set up the TIFF file with more realistic parameters
    uint32_t width = data[0] + 1; // Ensure non-zero width
    uint32_t length = data[1] + 1; // Ensure non-zero length
    uint16_t samplesPerPixel = data[2] % 4 + 1; // 1 to 4 samples per pixel
    uint16_t bitsPerSample = (data[3] % 3 + 1) * 8; // 8, 16, or 24 bits per sample
    uint16_t compression = data[4] % 2 == 0 ? COMPRESSION_NONE : COMPRESSION_LZW; // Add compression option
    uint16_t photometric = data[5] % 2 == 0 ? PHOTOMETRIC_MINISBLACK : PHOTOMETRIC_RGB; // Add photometric option

    if (!TIFFSetField(tiff, TIFFTAG_IMAGEWIDTH, width) ||
        !TIFFSetField(tiff, TIFFTAG_IMAGELENGTH, length) ||
        !TIFFSetField(tiff, TIFFTAG_SAMPLESPERPIXEL, samplesPerPixel) ||
        !TIFFSetField(tiff, TIFFTAG_BITSPERSAMPLE, bitsPerSample) ||
        !TIFFSetField(tiff, TIFFTAG_COMPRESSION, compression) ||
        !TIFFSetField(tiff, TIFFTAG_PHOTOMETRIC, photometric) ||
        !TIFFSetField(tiff, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT) ||
        !TIFFSetField(tiff, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG)) {
        TIFFClose(tiff);
        remove(tmpl);
        return 0;
    }

    // Calculate tile size and ensure it's within the buffer size
    tmsize_t tileSize = TIFFTileSize(tiff);
    if (tileSize > bufferSize) {
        tileSize = bufferSize;
    }

    // Write multiple tiles if possible to increase code coverage
    for (tileIndex = 0; tileIndex < TIFFNumberOfTiles(tiff); ++tileIndex) {
        tmsize_t offset = tileIndex * tileSize;
        if (offset + tileSize > bufferSize) {
            tileSize = bufferSize - offset;
        }
        if (tileSize <= 0) {
            break;
        }
        if (TIFFWriteEncodedTile(tiff, tileIndex, (void *)(data + offset), tileSize) == -1) {
            break;
        }
    }

    // Close the TIFF file after writing
    TIFFClose(tiff);

    // Reopen the TIFF file for reading to exercise the read functionality
    tiff = TIFFOpen(tmpl, "r");
    if (tiff != nullptr) {
        // Read the image data back
        uint32_t readWidth, readLength;
        uint16_t readSamplesPerPixel, readBitsPerSample, readCompression, readPhotometric;

        TIFFGetField(tiff, TIFFTAG_IMAGEWIDTH, &readWidth);
        TIFFGetField(tiff, TIFFTAG_IMAGELENGTH, &readLength);
        TIFFGetField(tiff, TIFFTAG_SAMPLESPERPIXEL, &readSamplesPerPixel);
        TIFFGetField(tiff, TIFFTAG_BITSPERSAMPLE, &readBitsPerSample);
        TIFFGetField(tiff, TIFFTAG_COMPRESSION, &readCompression);
        TIFFGetField(tiff, TIFFTAG_PHOTOMETRIC, &readPhotometric);

        // Optionally, read the image data into a buffer
        tmsize_t readTileSize = TIFFTileSize(tiff);
        if (readTileSize > 0) {
            void *buffer = _TIFFmalloc(readTileSize);
            if (buffer) {
                for (tileIndex = 0; tileIndex < TIFFNumberOfTiles(tiff); ++tileIndex) {
                    if (TIFFReadEncodedTile(tiff, tileIndex, buffer, readTileSize) == -1) {
                        break;
                    }
                }
                _TIFFfree(buffer);
            }
        }

        // Close the TIFF file after reading
        TIFFClose(tiff);
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_136(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
