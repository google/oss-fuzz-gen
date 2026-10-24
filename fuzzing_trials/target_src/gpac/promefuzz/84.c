// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_text_add_blink at tx3g.c:399:8 in isomedia.h
// gf_isom_text_add_highlight at tx3g.c:306:8 in isomedia.h
// gf_isom_text_add_hyperlink at tx3g.c:370:8 in isomedia.h
// gf_isom_text_set_karaoke_segment at tx3g.c:345:8 in isomedia.h
// gf_isom_text_reset_styles at tx3g.c:612:8 in isomedia.h
// gf_isom_text_reset at tx3g.c:636:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

// Define the structure since it's incomplete in the header
struct _3gpp_text_sample {
    char *text;
    u32 len;
    void *styles; // Placeholder for GF_TextStyleBox
    void *highlight_color; // Placeholder for GF_TextHighlightColorBox
    void *scroll_delay; // Placeholder for GF_TextScrollDelayBox
    void *box; // Placeholder for GF_TextBoxBox
    void *wrap; // Placeholder for GF_TextWrapBox
    Bool is_forced;
    GF_List *others;
    void *cur_karaoke; // Placeholder for GF_TextKaraokeBox
};

static GF_TextSample* create_text_sample() {
    // Allocate memory for GF_TextSample
    GF_TextSample *sample = (GF_TextSample*)malloc(sizeof(GF_TextSample));
    if (sample) {
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

static void free_text_sample(GF_TextSample *sample) {
    if (sample) {
        free(sample->text);
        free(sample);
    }
}

int LLVMFuzzerTestOneInput_84(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    GF_TextSample *sample = create_text_sample();
    if (!sample) return 0;

    u16 start_char = Data[0];
    u16 end_char = Data[1];

    // Fuzz gf_isom_text_add_blink
    gf_isom_text_add_blink(sample, start_char, end_char);

    // Fuzz gf_isom_text_add_highlight
    gf_isom_text_add_highlight(sample, start_char, end_char);

    // Fuzz gf_isom_text_add_hyperlink
    char *url = "http://example.com";
    char *altString = "tooltip";
    gf_isom_text_add_hyperlink(sample, url, altString, start_char, end_char);

    // Fuzz gf_isom_text_set_karaoke_segment
    if (Size >= 6) {
        u32 end_time = *(u32*)(Data + 2);
        gf_isom_text_set_karaoke_segment(sample, end_time, start_char, end_char);
    }

    // Fuzz gf_isom_text_reset_styles
    gf_isom_text_reset_styles(sample);

    // Fuzz gf_isom_text_reset
    gf_isom_text_reset(sample);

    free_text_sample(sample);
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

        LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    