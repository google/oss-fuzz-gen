#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

typedef struct _3gpp_text_sample {
    char *text;
    u32 len;

    void *styles;
    void *highlight_color;
    void *scroll_delay;
    void *box;
    void *wrap;
    int is_forced;

    void *others;
    void *cur_karaoke;
} GF_TextSample;

static GF_TextSample* create_text_sample() {
    GF_TextSample* sample = (GF_TextSample*)malloc(sizeof(GF_TextSample));
    if (!sample) return NULL;
    memset(sample, 0, sizeof(GF_TextSample));
    return sample;
}

static void destroy_text_sample(GF_TextSample* sample) {
    if (!sample) return;
    free(sample->text);
    free(sample);
}

int LLVMFuzzerTestOneInput_146(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure there's enough data for u32

    GF_TextSample* sample = create_text_sample();
    if (!sample) return 0;

    u32 value = *(u32*)Data;
    const char* text_data = (const char*)(Data + sizeof(u32));
    u32 text_len = Size - sizeof(u32);

    // Fuzz gf_isom_text_set_scroll_delay
    gf_isom_text_set_scroll_delay(sample, value);

    // Fuzz gf_isom_text_add_karaoke
    gf_isom_text_add_karaoke(sample, value);

    // Fuzz gf_isom_text_set_highlight_color
    gf_isom_text_set_highlight_color(sample, value);

    // Fuzz gf_isom_text_reset_styles
    gf_isom_text_reset_styles(sample);

    // Fuzz gf_isom_text_add_text
    gf_isom_text_add_text(sample, (char *)text_data, text_len);

    // Fuzz gf_isom_text_reset
    gf_isom_text_reset(sample);

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

    LLVMFuzzerTestOneInput_146(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
