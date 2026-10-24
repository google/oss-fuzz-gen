// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_text_set_scroll_delay at tx3g.c:358:8 in isomedia.h
// gf_isom_text_add_karaoke at tx3g.c:335:8 in isomedia.h
// gf_isom_text_sample_size at tx3g.c:498:5 in isomedia.h
// gf_isom_text_set_highlight_color at tx3g.c:321:8 in isomedia.h
// gf_isom_text_set_karaoke_segment at tx3g.c:345:8 in isomedia.h
// gf_isom_text_add_text at tx3g.c:259:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

// Dummy definitions for incomplete types
struct GF_TextKaraokeBox {};
struct GF_TextWrapBox {};
struct GF_TextBoxBox {};
struct GF_TextScrollDelayBox {};
struct GF_TextHighlightColorBox {};
struct GF_TextStyleBox {};
struct GF_List {};

typedef struct _3gpp_text_sample {
    char *text;
    u32 len;
    struct GF_TextStyleBox *styles;
    struct GF_TextHighlightColorBox *highlight_color;
    struct GF_TextScrollDelayBox *scroll_delay;
    struct GF_TextBoxBox *box;
    struct GF_TextWrapBox *wrap;
    int is_forced;
    struct GF_List *others;
    struct GF_TextKaraokeBox *cur_karaoke;
} GF_TextSample;

static GF_TextSample* create_text_sample() {
    GF_TextSample *sample = (GF_TextSample *)malloc(sizeof(GF_TextSample));
    if (sample) {
        memset(sample, 0, sizeof(GF_TextSample));
        sample->text = NULL;
        sample->len = 0;
        sample->styles = NULL;
        sample->highlight_color = NULL;
        sample->scroll_delay = NULL;
        sample->box = NULL;
        sample->wrap = NULL;
        sample->is_forced = 0;
        sample->others = NULL;
        sample->cur_karaoke = NULL;
    }
    return sample;
}

static void destroy_text_sample(GF_TextSample *sample) {
    if (sample) {
        free(sample->text);
        free(sample);
    }
}

int LLVMFuzzerTestOneInput_243(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    GF_TextSample *sample = create_text_sample();
    if (!sample) return 0;

    u32 scroll_delay = *(u32 *)Data;
    u32 start_time = scroll_delay;
    u32 end_time = scroll_delay;
    u16 start_char = (u16)(scroll_delay & 0xFFFF);
    u16 end_char = (u16)((scroll_delay >> 16) & 0xFFFF);
    u32 argb_color = scroll_delay;
    char *text_data = (char *)Data;
    u32 text_len = Size;

    gf_isom_text_set_scroll_delay(sample, scroll_delay);
    gf_isom_text_add_karaoke(sample, start_time);
    gf_isom_text_sample_size(sample);
    gf_isom_text_set_highlight_color(sample, argb_color);
    gf_isom_text_set_karaoke_segment(sample, end_time, start_char, end_char);
    gf_isom_text_add_text(sample, text_data, text_len);

    destroy_text_sample(sample);
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

        LLVMFuzzerTestOneInput_243(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    