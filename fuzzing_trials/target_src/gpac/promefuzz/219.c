// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_add_user_data at isom_write.c:3803:8 in isomedia.h
// gf_isom_remove_uuid at isom_write.c:6227:8 in isomedia.h
// gf_isom_remove_user_data_item at isom_write.c:3705:8 in isomedia.h
// gf_isom_add_uuid at isom_write.c:6258:8 in isomedia.h
// gf_isom_add_user_data_boxes at isom_write.c:3856:8 in isomedia.h
// gf_isom_remove_user_data at isom_write.c:3758:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

#define MIN_SIZE (sizeof(u32) * 2 + sizeof(bin128) + sizeof(u32))

static void initialize_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_219(const uint8_t *Data, size_t Size) {
    if (Size < MIN_SIZE) {
        return 0; // Not enough data to proceed
    }

    // Initialize variables
    GF_ISOFile *isom_file = NULL; // We cannot directly get this from Data
    u32 trackNumber = *(u32 *)(Data);
    u32 UserDataType = *(u32 *)(Data + sizeof(u32));
    bin128 UUID;
    memcpy(UUID, Data + sizeof(u32) * 2, sizeof(bin128));
    u8 *data = (u8 *)(Data + sizeof(u32) * 2 + sizeof(bin128));
    u32 size = Size - MIN_SIZE;

    // Prepare a dummy file
    initialize_dummy_file(Data, Size);

    // Fuzz gf_isom_add_user_data
    GF_Err err = gf_isom_add_user_data(isom_file, trackNumber, UserDataType, UUID, data, size);
    if (err != GF_OK) {
        // Handle error if needed
    }

    // Fuzz gf_isom_remove_uuid
    err = gf_isom_remove_uuid(isom_file, trackNumber, UUID);
    if (err != GF_OK) {
        // Handle error if needed
    }

    // Fuzz gf_isom_remove_user_data_item
    u32 UserDataIndex = trackNumber % 10; // Arbitrary index for fuzzing
    err = gf_isom_remove_user_data_item(isom_file, trackNumber, UserDataType, UUID, UserDataIndex);
    if (err != GF_OK) {
        // Handle error if needed
    }

    // Fuzz gf_isom_add_uuid
    err = gf_isom_add_uuid(isom_file, trackNumber, UUID, data, size);
    if (err != GF_OK) {
        // Handle error if needed
    }

    // Fuzz gf_isom_add_user_data_boxes
    err = gf_isom_add_user_data_boxes(isom_file, trackNumber, data, size);
    if (err != GF_OK) {
        // Handle error if needed
    }

    // Fuzz gf_isom_remove_user_data
    err = gf_isom_remove_user_data(isom_file, trackNumber, UserDataType, UUID);
    if (err != GF_OK) {
        // Handle error if needed
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

        LLVMFuzzerTestOneInput_219(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    