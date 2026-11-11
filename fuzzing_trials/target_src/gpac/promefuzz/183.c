// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_text_add_style at tx3g.c:290:8 in isomedia.h
// gf_isom_text_set_box at tx3g.c:384:8 in isomedia.h
// gf_isom_text_set_forced at tx3g.c:423:8 in isomedia.h
// gf_isom_text_sample_write_bs at tx3g.c:440:8 in isomedia.h
// gf_isom_text_reset_styles at tx3g.c:612:8 in isomedia.h
// gf_isom_text_reset at tx3g.c:636:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

// Define the struct _3gpp_text_sample as per the provided related data types
struct _3gpp_text_sample {
    char *text;
    u32 len;
    void *styles;
    void *highlight_color;
    void *scroll_delay;
    void *box;
    void *wrap;
    Bool is_forced;
    GF_List *others;
    void *cur_karaoke;
};

// Define the struct __tag_bitstream as per the provided related data types
struct __tag_bitstream {
    FILE *stream;
    char *original;
    u64 size;
    u64 position;
    u32 current;
    u32 nbBits;
    u32 bsmode;
    void (*EndOfStream)(void *par);
    void *par;
    char *cache_write;
    u32 cache_write_size, buffer_written;
    Bool remove_emul_prevention_byte;
    u32 nb_zeros, nb_removed;
    GF_Err (*on_block_out)(void *cbk, u8 *data, u32 block_size);
    void *usr_data;
    u64 bytes_out;
    u32 prevent_dispatch;
    u64 cookie;
    u8 *cache_read;
    u32 cache_read_size, cache_read_pos, cache_read_alloc;
    void (*on_log)(void *udta, const char *field_name, u32 nb_bits, u64 field_val, s32 idx1, s32 idx2, s32 idx3);
    void *log_udta;
    u32 total_bits_read;
    u32 overflow_state;
    u64 o_size;
#ifdef GPAC_HAS_FD
    int fd;
#endif
};

static void initialize_text_sample(GF_TextSample *tx_samp) {
    if (!tx_samp) return;
    tx_samp->text = NULL;
    tx_samp->len = 0;
    tx_samp->styles = NULL;
    tx_samp->highlight_color = NULL;
    tx_samp->scroll_delay = NULL;
    tx_samp->box = NULL;
    tx_samp->wrap = NULL;
    tx_samp->is_forced = 0;
    tx_samp->others = NULL;
    tx_samp->cur_karaoke = NULL;
}

static void initialize_bitstream(GF_BitStream *bs) {
    if (!bs) return;
    bs->stream = NULL;
    bs->original = (char *)malloc(1024); // Allocate some memory for the bitstream
    bs->size = 1024; // Set the size of the buffer
    bs->position = 0;
    bs->current = 0;
    bs->nbBits = 0; // Ensure the bitstream is byte-aligned
    bs->bsmode = 0;
    bs->EndOfStream = NULL;
    bs->par = NULL;
    bs->cache_write = NULL;
    bs->cache_write_size = 0;
    bs->buffer_written = 0;
    bs->remove_emul_prevention_byte = 0;
    bs->nb_zeros = 0;
    bs->nb_removed = 0;
    bs->on_block_out = NULL;
    bs->usr_data = NULL;
    bs->bytes_out = 0;
    bs->prevent_dispatch = 0;
    bs->cookie = 0;
    bs->cache_read = NULL;
    bs->cache_read_size = 0;
    bs->cache_read_pos = 0;
    bs->cache_read_alloc = 0;
    bs->on_log = NULL;
    bs->log_udta = NULL;
    bs->total_bits_read = 0;
    bs->overflow_state = 0;
    bs->o_size = 0;
}

int LLVMFuzzerTestOneInput_183(const uint8_t *Data, size_t Size) {
    GF_TextSample text_sample;
    GF_StyleRecord style_record;
    GF_BitStream bitstream;
    GF_Err result;

    initialize_text_sample(&text_sample);
    initialize_bitstream(&bitstream);

    // Fuzz gf_isom_text_add_style
    if (Size >= sizeof(GF_StyleRecord)) {
        memcpy(&style_record, Data, sizeof(GF_StyleRecord));
        result = gf_isom_text_add_style(&text_sample, &style_record);
    }

    // Fuzz gf_isom_text_set_box
    if (Size >= sizeof(s16) * 4) {
        s16 top, left, bottom, right;
        memcpy(&top, Data, sizeof(s16));
        memcpy(&left, Data + sizeof(s16), sizeof(s16));
        memcpy(&bottom, Data + 2 * sizeof(s16), sizeof(s16));
        memcpy(&right, Data + 3 * sizeof(s16), sizeof(s16));
        result = gf_isom_text_set_box(&text_sample, top, left, bottom, right);
    }

    // Fuzz gf_isom_text_set_forced
    if (Size > 0) {
        Bool is_forced = Data[0] % 2; // Use first byte to set forced flag
        result = gf_isom_text_set_forced(&text_sample, is_forced);
    }

    // Fuzz gf_isom_text_sample_write_bs
    if (Size >= sizeof(GF_BitStream)) {
        // Ensure the bitstream is properly initialized and byte-aligned before use
        initialize_bitstream(&bitstream);
        result = gf_isom_text_sample_write_bs(&text_sample, &bitstream);
    }

    // Fuzz gf_isom_text_reset_styles
    result = gf_isom_text_reset_styles(&text_sample);

    // Fuzz gf_isom_text_reset
    result = gf_isom_text_reset(&text_sample);

    // Cleanup
    if (text_sample.text) {
        free(text_sample.text);
    }
    if (text_sample.styles) {
        free(text_sample.styles);
    }
    if (bitstream.original) {
        free(bitstream.original);
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

        LLVMFuzzerTestOneInput_183(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    