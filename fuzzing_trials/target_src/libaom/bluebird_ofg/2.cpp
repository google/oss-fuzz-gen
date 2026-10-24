#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstddef>
#include <iostream> // Include for debugging output

extern "C" {
    #include "/src/aom/aom/aom_codec.h"
    #include "aom/aom_decoder.h"
    #include "aom/aomdx.h"
}

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    const aom_codec_iface_t *iface = aom_codec_av1_dx();

    aom_codec_ctx_t codec;
    aom_codec_err_t res = aom_codec_dec_init(&codec, iface, nullptr, 0);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Failed to initialize codec: " << aom_codec_err_to_string(res) << std::endl;
        return 0;
    }

    res = aom_codec_decode(&codec, data, size, nullptr);
    if (res != AOM_CODEC_OK) {
        std::cerr << "Failed to decode: " << aom_codec_err_to_string(res) << std::endl;
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from aom_codec_decode to aom_codec_set_frame_buffer_functions
    aom_image_t ohnjtcyv;
    memset(&ohnjtcyv, 0, sizeof(ohnjtcyv));
    aom_img_flip(&ohnjtcyv);
    aom_codec_err_t ret_aom_codec_set_frame_buffer_functions_ggkip = aom_codec_set_frame_buffer_functions(&codec, 0, 0, (void *)&ohnjtcyv);
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from aom_codec_set_frame_buffer_functions to aom_codec_control

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from aom_codec_set_frame_buffer_functions to aom_codec_dec_init_ver
    // Ensure dataflow is valid (i.e., non-null)
    if (!iface) {
    	return 0;
    }
    const char* ret_aom_codec_iface_name_mhyqr = aom_codec_iface_name(iface);
    if (ret_aom_codec_iface_name_mhyqr == NULL){
    	return 0;
    }
    aom_codec_caps_t ret_aom_codec_get_caps_upqga = aom_codec_get_caps(NULL);
    if (ret_aom_codec_get_caps_upqga < 0){
    	return 0;
    }
    size_t ret_aom_uleb_size_in_bytes_kbjqj = aom_uleb_size_in_bytes(-1);
    if (ret_aom_uleb_size_in_bytes_kbjqj < 0){
    	return 0;
    }
    aom_codec_dec_cfg_t zzypuysf;
    memset(&zzypuysf, 0, sizeof(zzypuysf));
    // Ensure dataflow is valid (i.e., non-null)
    if (!iface) {
    	return 0;
    }
    aom_codec_err_t ret_aom_codec_dec_init_ver_xgwqj = aom_codec_dec_init_ver(&codec, iface, &zzypuysf, ret_aom_codec_get_caps_upqga, (int )ret_aom_uleb_size_in_bytes_kbjqj);
    // End mutation: Producer.APPEND_MUTATOR
    
    aom_codec_err_t ret_aom_codec_control_mbrmt = aom_codec_control(&codec, size);
    // End mutation: Producer.APPEND_MUTATOR
    
    aom_codec_iter_t iter = nullptr;
    aom_image_t *img = nullptr;
    while ((img = aom_codec_get_frame(&codec, &iter)) != nullptr) {
        // Process the image (img) if needed
    }

    aom_codec_destroy(&codec);

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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
