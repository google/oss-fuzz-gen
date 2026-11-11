#include <string.h>
#include <sys/stat.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <iostream>
#include <fstream>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "aom/aomdx.h"
#include "/src/aom/aom/aom.h"
#include "/src/aom/aom/aom_codec.h"
#include "aom/aom_decoder.h"
#include "/src/aom/aom/aom_image.h"

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Initialize codec context
    aom_codec_ctx_t codec_ctx;
    aom_codec_iface_t *iface = aom_codec_av1_dx();
    aom_codec_dec_cfg_t cfg = {0};
    aom_codec_flags_t flags = 0;
    int ver = AOM_DECODER_ABI_VERSION;

    // Initialize the decoder
    if (aom_codec_dec_init_ver(&codec_ctx, iface, &cfg, flags, ver) != AOM_CODEC_OK) {
        return 0;
    }

    // Prepare aom_codec_stream_info_t
    aom_codec_stream_info_t stream_info;
    stream_info.w = 0;

    // Peek stream info
    if (aom_codec_peek_stream_info(iface, Data, Size, &stream_info) == AOM_CODEC_OK) {
        // Decode the input data
        if (aom_codec_decode(&codec_ctx, Data, Size, nullptr) == AOM_CODEC_OK) {
            // Retrieve frames
            aom_codec_iter_t iter = nullptr;
            aom_image_t *img;
            while ((img = aom_codec_get_frame(&codec_ctx, &iter)) != nullptr) {
                // Process the image (img)
                // For the purpose of fuzzing, we don't need to do anything with img
            }
        }
    }

    // Get stream info after decoding
    if (aom_codec_get_stream_info(&codec_ctx, &stream_info) != AOM_CODEC_OK) {
        // Handle error in getting stream info
    }

    // Destroy the codec context

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from aom_codec_peek_stream_info to aom_codec_dec_init_ver
    size_t ret_aom_uleb_size_in_bytes_uhqvw = aom_uleb_size_in_bytes(AOM_PLANE_PACKED);
    if (ret_aom_uleb_size_in_bytes_uhqvw < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!iface) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from aom_uleb_size_in_bytes to aom_uleb_encode_fixed_size
    aom_image_t fddixetj;
    memset(&fddixetj, 0, sizeof(fddixetj));
    size_t ret_aom_img_num_metadata_ukiob = aom_img_num_metadata(&fddixetj);
    if (ret_aom_img_num_metadata_ukiob < 0){
    	return 0;
    }
    size_t ret_aom_img_num_metadata_shqcn = aom_img_num_metadata(NULL);
    if (ret_aom_img_num_metadata_shqcn < 0){
    	return 0;
    }
    aom_image_t rzmruhxn;
    memset(&rzmruhxn, 0, sizeof(rzmruhxn));
    size_t ret_aom_img_num_metadata_xwegi = aom_img_num_metadata(&rzmruhxn);
    if (ret_aom_img_num_metadata_xwegi < 0){
    	return 0;
    }
    int ret_aom_uleb_encode_fixed_size_vpsgf = aom_uleb_encode_fixed_size((uint64_t )ret_aom_img_num_metadata_ukiob, ret_aom_uleb_size_in_bytes_uhqvw, ret_aom_uleb_size_in_bytes_uhqvw, (uint8_t *)&ret_aom_img_num_metadata_shqcn, &ret_aom_img_num_metadata_xwegi);
    if (ret_aom_uleb_encode_fixed_size_vpsgf < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    aom_codec_caps_t ret_aom_codec_get_caps_izlnn = aom_codec_get_caps(iface);
    if (ret_aom_codec_get_caps_izlnn < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!iface) {
    	return 0;
    }
    aom_codec_err_t ret_aom_codec_dec_init_ver_kpaoy = aom_codec_dec_init_ver(&codec_ctx, iface, NULL, (long )ret_aom_uleb_size_in_bytes_uhqvw, (int )ret_aom_codec_get_caps_izlnn);
    // End mutation: Producer.APPEND_MUTATOR
    
    aom_codec_destroy(&codec_ctx);

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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
