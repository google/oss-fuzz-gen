#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "htp/htp.h"
#include "htp/htp.h"
#include "htp/htp.h"
#include "htp/htp.h"
#include "/src/libhtp/htp/bstr.h"

static bstr *create_bstr(const uint8_t *data, size_t size) {
    bstr *b = (bstr *)malloc(sizeof(bstr));
    if (!b) return NULL;
    b->realptr = (unsigned char *)malloc(size);
    if (!b->realptr) {
        free(b);
        return NULL;
    }
    memcpy(b->realptr, data, size);
    b->len = size;
    b->size = size;
    return b;
}

static void free_bstr(bstr *b) {
    if (b) {
        free(b->realptr);
        free(b);
    }
}

int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz bstr_add_mem_noex
    bstr *b1 = create_bstr(Data, Size);
    if (b1) {
        bstr *result = bstr_add_mem_noex(b1, Data, Size);
        (void)result; // Use result if needed
        free_bstr(b1);
    }

    // Fuzz htp_urldecode_inplace
    if (Size >= sizeof(bstr) + sizeof(uint64_t)) {
        htp_cfg_t *cfg = htp_config_create();
        if (cfg) {
            enum htp_decoder_ctx_t ctx = HTP_DECODER_URLENCODED;
            bstr *input = create_bstr(Data, Size - sizeof(uint64_t));
            uint64_t flags = 0;
            if (input) {
                htp_status_t status = htp_urldecode_inplace(cfg, ctx, input, &flags);
                (void)status; // Use status if needed
                free_bstr(input);
            }
            htp_config_destroy(cfg);
        }
    }

    // Fuzz htp_urldecode_inplace_ex
    if (Size >= sizeof(bstr) + sizeof(uint64_t) + sizeof(int)) {
        htp_cfg_t *cfg = htp_config_create();
        if (cfg) {
            enum htp_decoder_ctx_t ctx = HTP_DECODER_URLENCODED;
            bstr *input = create_bstr(Data, Size - sizeof(uint64_t) - sizeof(int));
            uint64_t flags = 0;
            int expected_status_code = 0;
            if (input) {
                htp_status_t status = htp_urldecode_inplace_ex(cfg, ctx, input, &flags, &expected_status_code);
                (void)status; // Use status if needed
                free_bstr(input);
            }
            htp_config_destroy(cfg);
        }
    }

    // Fuzz bstr_to_lowercase
    bstr *b2 = create_bstr(Data, Size);
    if (b2) {
        bstr *result = bstr_to_lowercase(b2);
        (void)result; // Use result if needed
        free_bstr(b2);
    }

    // Fuzz bstr_adjust_len
    bstr *b3 = create_bstr(Data, Size);
    if (b3) {
        size_t new_len = Size / 2; // Adjust length to half
        bstr_adjust_len(b3, new_len);
        free_bstr(b3);
    }

    // Fuzz bstr_adjust_size
    bstr *b4 = create_bstr(Data, Size);
    if (b4) {
        size_t new_size = Size * 2; // Adjust size to double
        bstr_adjust_size(b4, new_size);
        free_bstr(b4);
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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
