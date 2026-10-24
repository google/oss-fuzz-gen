#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include "sstream"
#include <string>
#include <vector>
#include "cstring"
#include "cstdlib"
#include <cstdio>
#include "cstdint"
#include <cstddef>
#include "tiffio.h"
#include "cstdint"
#include "cstring"
#include <iostream>
#include <fstream>

static TIFF* createDummyTIFF() {
    std::ofstream dummyFile("./dummy_file", std::ios::binary);
    if (!dummyFile) {
        std::cerr << "Failed to create dummy file." << std::endl;
        return nullptr;
    }
    // Write minimal TIFF header to dummy file
    char header[] = "II*\0"; // Little-endian, TIFF magic number
    dummyFile.write(header, sizeof(header));
    dummyFile.close();
    
    return TIFFOpen("./dummy_file", "r+");
}

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least one byte to read

    TIFF* tif = createDummyTIFF();
    if (!tif) return 0;

    // Fuzz TIFFReadEncodedStrip
    uint32_t strip = 0;
    tmsize_t bufSize = 1024; // Arbitrary buffer size
    void* buf = malloc(bufSize);
    if (buf) {
        tmsize_t bytesRead = TIFFReadEncodedStrip(tif, strip, buf, bufSize);
        if (bytesRead == -1) {
            std::cerr << "Error reading encoded strip." << std::endl;
        }
        free(buf);
    }

    // Fuzz TIFFIsCODECConfigured
    uint16_t scheme = Data[0]; // Use the first byte as codec scheme
    int isConfigured = TIFFIsCODECConfigured(scheme);
    if (isConfigured == 1) {
        std::cout << "Codec is configured." << std::endl;
    }

    // Fuzz TIFFRegisterCODEC
    TIFFCodec* codec = TIFFRegisterCODEC(scheme, "DummyCodec", nullptr);
    if (codec) {
        std::cout << "Codec registered successfully." << std::endl;
    }

    // Fuzz TIFFFindCODEC
    const TIFFCodec* foundCodec = TIFFFindCODEC(scheme);
    if (foundCodec) {
        std::cout << "Codec found." << std::endl;
    }

    // Fuzz TIFFGetConfiguredCODECs
    TIFFCodec* codecs = TIFFGetConfiguredCODECs();
    if (codecs) {
        std::cout << "Configured codecs retrieved." << std::endl;
        _TIFFfree(codecs);
    }

    // Fuzz TIFFUnRegisterCODEC
    if (codec) {
        TIFFUnRegisterCODEC(codec);
        std::cout << "Codec unregistered." << std::endl;
    }

    TIFFClose(tif);
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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
