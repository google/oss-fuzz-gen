// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_uleb_encode at aom_integer.c:58:5 in aom_integer.h
// aom_img_add_metadata at aom_image.c:390:5 in aom_image.h
// aom_img_remove_metadata at aom_image.c:422:6 in aom_image.h
// aom_uleb_encode_fixed_size at aom_integer.c:79:5 in aom_integer.h
// aom_uleb_size_in_bytes at aom_integer.c:23:8 in aom_integer.h
// aom_uleb_decode at aom_integer.c:31:5 in aom_integer.h
// aom_img_num_metadata at aom_image.c:439:8 in aom_image.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include "aomdx.h"
#include "aom.h"
#include "aom_codec.h"
#include "aom_external_partition.h"
#include "aom_decoder.h"
#include "aomcx.h"
#include "aom_integer.h"
#include "aom_frame_buffer.h"
#include "aom_image.h"
#include "aom_encoder.h"

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    // Fuzz aom_uleb_encode
    if (Size >= sizeof(uint64_t) + sizeof(size_t)) {
        uint64_t value;
        size_t available;
        memcpy(&value, Data, sizeof(uint64_t));
        memcpy(&available, Data + sizeof(uint64_t), sizeof(size_t));

        uint8_t coded_value[10]; // LEB128 can use up to 10 bytes
        size_t coded_size = 0;
        aom_uleb_encode(value, available, coded_value, &coded_size);
    }

    // Fuzz aom_img_add_metadata
    if (Size >= sizeof(aom_image_t) + sizeof(uint32_t) + sizeof(size_t) + sizeof(aom_metadata_insert_flags_t)) {
        aom_image_t img;
        uint32_t type;
        size_t sz;
        aom_metadata_insert_flags_t insert_flag;

        memcpy(&img, Data, sizeof(aom_image_t));
        memcpy(&type, Data + sizeof(aom_image_t), sizeof(uint32_t));
        memcpy(&sz, Data + sizeof(aom_image_t) + sizeof(uint32_t), sizeof(size_t));
        memcpy(&insert_flag, Data + sizeof(aom_image_t) + sizeof(uint32_t) + sizeof(size_t), sizeof(aom_metadata_insert_flags_t));

        const uint8_t *metadata_data = Data + sizeof(aom_image_t) + sizeof(uint32_t) + sizeof(size_t) + sizeof(aom_metadata_insert_flags_t);

        if (Size >= sizeof(aom_image_t) + sizeof(uint32_t) + sizeof(size_t) + sizeof(aom_metadata_insert_flags_t) + sz) {
            img.metadata = nullptr; // Initialize metadata to avoid leaks
            aom_img_add_metadata(&img, type, metadata_data, sz, insert_flag);
            // Clean up metadata to prevent leaks
            if (img.metadata != nullptr) {
                aom_img_remove_metadata(&img);
            }
        }
    }

    // Fuzz aom_uleb_encode_fixed_size
    if (Size >= sizeof(uint64_t) + 2 * sizeof(size_t)) {
        uint64_t value;
        size_t available, pad_to_size;
        memcpy(&value, Data, sizeof(uint64_t));
        memcpy(&available, Data + sizeof(uint64_t), sizeof(size_t));
        memcpy(&pad_to_size, Data + sizeof(uint64_t) + sizeof(size_t), sizeof(size_t));

        uint8_t coded_value[10];
        size_t coded_size = 0;
        aom_uleb_encode_fixed_size(value, available, pad_to_size, coded_value, &coded_size);
    }

    // Fuzz aom_uleb_size_in_bytes
    if (Size >= sizeof(uint64_t)) {
        uint64_t value;
        memcpy(&value, Data, sizeof(uint64_t));

        size_t size_in_bytes = aom_uleb_size_in_bytes(value);
    }

    // Fuzz aom_uleb_decode
    if (Size >= 1) {
        uint64_t value;
        size_t length = 0;

        aom_uleb_decode(Data, Size, &value, &length);
    }

    // Fuzz aom_img_num_metadata
    if (Size >= sizeof(aom_image_t)) {
        aom_image_t img;
        memcpy(&img, Data, sizeof(aom_image_t));

        // Ensure metadata is initialized to avoid dereferencing null pointers
        img.metadata = nullptr;

        size_t num_metadata = aom_img_num_metadata(&img);
    }

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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    