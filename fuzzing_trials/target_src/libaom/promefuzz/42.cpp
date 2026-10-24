// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_img_metadata_alloc at aom_image.c:337:17 in aom_image.h
// aom_img_add_metadata at aom_image.c:390:5 in aom_image.h
// aom_img_num_metadata at aom_image.c:439:8 in aom_image.h
// aom_img_get_metadata at aom_image.c:429:23 in aom_image.h
// aom_img_metadata_free at aom_image.c:355:6 in aom_image.h
// aom_img_remove_metadata at aom_image.c:422:6 in aom_image.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include "aom.h"
#include "aom_image.h"
#include "aom_codec.h"
#include "aom_decoder.h"
#include "aom_encoder.h"
#include "aomcx.h"
#include "aomdx.h"
#include "aom_external_partition.h"
#include "aom_frame_buffer.h"
#include "aom_integer.h"

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t) + sizeof(size_t) + 1) {
        return 0;
    }

    // Extract metadata type, size and flag from data
    uint32_t type = *(reinterpret_cast<const uint32_t*>(Data));
    size_t metadata_size = *(reinterpret_cast<const size_t*>(Data + sizeof(uint32_t)));
    aom_metadata_insert_flags_t insert_flag = static_cast<aom_metadata_insert_flags_t>(Data[sizeof(uint32_t) + sizeof(size_t)]);

    // Ensure metadata_size does not exceed available data
    if (metadata_size > Size - (sizeof(uint32_t) + sizeof(size_t) + 1)) {
        metadata_size = Size - (sizeof(uint32_t) + sizeof(size_t) + 1);
    }

    const uint8_t *metadata_data = Data + sizeof(uint32_t) + sizeof(size_t) + 1;

    // Create a dummy aom_image_t
    aom_image_t img;
    memset(&img, 0, sizeof(aom_image_t));

    // Attempt to allocate metadata
    aom_metadata_t *metadata = aom_img_metadata_alloc(type, metadata_data, metadata_size, insert_flag);
    if (metadata) {
        // Attempt to add metadata to image
        int add_result = aom_img_add_metadata(&img, type, metadata_data, metadata_size, insert_flag);

        // Retrieve metadata count
        size_t num_metadata = aom_img_num_metadata(&img);

        // Access each metadata item
        for (size_t i = 0; i < num_metadata; ++i) {
            const aom_metadata_t *retrieved_metadata = aom_img_get_metadata(&img, i);
            if (retrieved_metadata) {
                // Process retrieved metadata if necessary
            }
        }

        // Free the allocated metadata
        aom_img_metadata_free(metadata);
    }

    // Remove all metadata from image
    aom_img_remove_metadata(&img);

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

        LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    