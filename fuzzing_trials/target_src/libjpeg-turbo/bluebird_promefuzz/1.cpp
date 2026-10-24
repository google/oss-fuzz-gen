#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "../src/turbojpeg.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }  // Ensure there is some data to process

    // Create a TurboJPEG instance handle
    tjhandle handle = tjInitCompress();
    if (!handle) {
        return 0;
    }

    // Allocate buffers for source and destination
    int width = 256;  // Example width
    int height = 256; // Example height
    int pixelSize = 3; // Assuming RGB format
    unsigned long compressedSize = tjBufSize(width, height, TJSAMP_444);
    std::vector<unsigned char> srcBuf(width * height * pixelSize);
    std::vector<unsigned char> dstBuf(compressedSize);

    // Copy data into the source buffer
    size_t copySize = std::min(Size, srcBuf.size());
    std::memcpy(srcBuf.data(), Data, copySize);

    // Define parameters for compression
    int pitch = width * pixelSize;
    int jpegSubsamp = TJSAMP_444;
    int jpegQual = 75;
    int flags = 0;

    // Call tjCompress
    int result = tjCompress(handle, srcBuf.data(), width, pitch, height, pixelSize,
                            dstBuf.data(), &compressedSize, jpegSubsamp, jpegQual, flags);

    // Check the result of the compression
    if (result == 0) {
        std::cout << "Compression successful, size: " << compressedSize << std::endl;
    } else {
        std::cerr << "Compression failed: " << tjGetErrorStr() << std::endl;
    }

    // Clean up
    tjDestroy(handle);

    // Now, let's fuzz tjDecompressToYUV
    handle = tjInitDecompress();
    if (!handle) {
        return 0;
    }

    std::vector<unsigned char> yuvBuf(width * height * pixelSize);

    // Call tjDecompressToYUV
    result = tjDecompressToYUV(handle, dstBuf.data(), compressedSize, yuvBuf.data(), flags);

    // Check the result of the decompression
    if (result == 0) {
        std::cout << "Decompression to YUV successful" << std::endl;
    } else {
        std::cerr << "Decompression to YUV failed: " << tjGetErrorStr() << std::endl;
    }

    // Clean up
    tjDestroy(handle);

    // Fuzz tjEncodeYUVPlanes
    handle = tjInitCompress();
    if (!handle) {
        return 0;
    }

    unsigned char *yuvPlanes[3] = { yuvBuf.data(), yuvBuf.data() + (width * height), yuvBuf.data() + (width * height * 2) };
    int strides[3] = { width, width / 2, width / 2 };

    result = tjEncodeYUVPlanes(handle, srcBuf.data(), width, pitch, height, TJPF_RGB,
                               yuvPlanes, strides, TJSAMP_444, flags);

    if (result == 0) {
        std::cout << "Encoding to YUV planes successful" << std::endl;
    } else {
        std::cerr << "Encoding to YUV planes failed: " << tjGetErrorStr() << std::endl;
    }

    // Clean up
    tjDestroy(handle);

    // Fuzz tjCompressFromYUV
    handle = tjInitCompress();
    if (!handle) {
        return 0;
    }


    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from tjInitCompress to tj3SetICCProfile using the plateau pool
    // Ensure dataflow is valid (i.e., non-null)
    if (!yuvPlanes) {
    	return 0;
    }
    int ret_tj3SetICCProfile_vrxzz = tj3SetICCProfile(handle, *yuvPlanes, (size_t )compressedSize);
    if (ret_tj3SetICCProfile_vrxzz < 0){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;

    result = tjCompressFromYUV(handle, yuvBuf.data(), width, 1, height, TJSAMP_444,
                               &jpegBuf, &jpegSize, jpegQual, flags);

    if (result == 0) {
        std::cout << "Compression from YUV successful, size: " << jpegSize << std::endl;
    } else {
        std::cerr << "Compression from YUV failed: " << tjGetErrorStr() << std::endl;
    }

    // Clean up
    tjFree(jpegBuf);
    tjDestroy(handle);

    // Fuzz tjDecompress
    handle = tjInitDecompress();
    if (!handle) {
        return 0;
    }

    std::vector<unsigned char> decompressedBuf(width * height * pixelSize);

    result = tjDecompress(handle, dstBuf.data(), compressedSize, decompressedBuf.data(),
                          width, pitch, height, pixelSize, flags);

    if (result == 0) {
        std::cout << "Decompression successful" << std::endl;
    } else {
        std::cerr << "Decompression failed: " << tjGetErrorStr() << std::endl;
    }

    // Clean up
    tjDestroy(handle);

    // Fuzz tjDecompressToYUVPlanes
    handle = tjInitDecompress();
    if (!handle) {
        return 0;
    }

    result = tjDecompressToYUVPlanes(handle, dstBuf.data(), compressedSize, yuvPlanes,
                                     width, strides, height, flags);

    if (result == 0) {
        std::cout << "Decompression to YUV planes successful" << std::endl;
    } else {
        std::cerr << "Decompression to YUV planes failed: " << tjGetErrorStr() << std::endl;
    }

    // Clean up
    tjDestroy(handle);

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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
