#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "/src/libyang/src/tree_data.h"

static void fuzz_ly_time_time2str(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(time_t) + 1) {
        return;
    }

    time_t time = *(time_t *)Data;
    const char *fractions_s = (const char *)(Data + sizeof(time_t));

    // Ensure fractions_s is null-terminated
    size_t fractions_len = Size - sizeof(time_t);
    char *fractions_s_null_terminated = (char *)malloc(fractions_len + 1);
    if (!fractions_s_null_terminated) {
        return;
    }
    memcpy(fractions_s_null_terminated, fractions_s, fractions_len);
    fractions_s_null_terminated[fractions_len] = '\0';

    char *str = NULL;
    ly_time_time2str(time, fractions_s_null_terminated, &str);
    free(str);
    free(fractions_s_null_terminated);
}

static void fuzz_ly_time_tz_offset(void) {
    ly_time_tz_offset();
}

static void fuzz_ly_time_tz_offset_at(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(time_t)) {
        return;
    }

    time_t time = *(time_t *)Data;
    ly_time_tz_offset_at(time);
}

static void fuzz_ly_time_str2time(const uint8_t *Data, size_t Size) {
    char *value = (char *)malloc(Size + 1);
    if (!value) {
        return;
    }
    memcpy(value, Data, Size);
    value[Size] = '\0';

    time_t time;
    char *fractions_s = NULL;
    ly_time_str2time(value, &time, &fractions_s);
    free(fractions_s);
    free(value);
}

static void fuzz_ly_time_ts2str(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct timespec)) {
        return;
    }

    struct timespec ts = *(struct timespec *)Data;
    char *str = NULL;

    ly_time_ts2str(&ts, &str);
    free(str);
}

static void fuzz_ly_time_str2ts(const uint8_t *Data, size_t Size) {
    char *value = (char *)malloc(Size + 1);
    if (!value) {
        return;
    }
    memcpy(value, Data, Size);
    value[Size] = '\0';

    struct timespec ts;
    ly_time_str2ts(value, &ts);
    free(value);
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    fuzz_ly_time_time2str(Data, Size);
    fuzz_ly_time_tz_offset();
    fuzz_ly_time_tz_offset_at(Data, Size);
    fuzz_ly_time_str2time(Data, Size);
    fuzz_ly_time_ts2str(Data, Size);
    fuzz_ly_time_str2ts(Data, Size);
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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
