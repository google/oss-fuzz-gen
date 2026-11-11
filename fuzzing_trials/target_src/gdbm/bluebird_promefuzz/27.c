#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "gdbmtool.h"

static void fuzz_pager_printf(PAGERFILE *pfp, const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return;
    }
    char *fmt = (char *)malloc(Size + 1);
    if (!fmt) {
        return;
    }
    memcpy(fmt, Data, Size);
    fmt[Size] = '\0';

    // Ensure the format string is valid by replacing any '%' with '%%'
    for (size_t i = 0; i < Size; ++i) {
        if (fmt[i] == '%') {
            fmt[i] = ' ';
        }
    }

    pager_printf(pfp, fmt);
    free(fmt);
}

static void fuzz_pager_writeln(PAGERFILE *pfp, const uint8_t *Data, size_t Size) {
    char *str = (char *)malloc(Size + 1);
    if (!str) {
        return;
    }
    memcpy(str, Data, Size);
    str[Size] = '\0';

    pager_writeln(pfp, str);
    free(str);
}

int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    FILE *dummy_file = fopen("./dummy_file", "w+");
    if (!dummy_file) {
        return 0;
    }

    PAGERFILE *pfp = pager_open(dummy_file, 10, "less");
    if (!pfp) {
        fclose(dummy_file);
        return 0;
    }

    fuzz_pager_printf(pfp, Data, Size);
    fuzz_pager_writeln(pfp, Data, Size);

    pager_close(pfp);

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from pager_close to pager_writez

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from pager_close to variable_set
    char ppbzbino[1024] = "nwmyd";
    struct slist* ret_slist_new_s_dqwow = slist_new_s(ppbzbino);
    if (ret_slist_new_s_dqwow == NULL){
    	return 0;
    }
    int ret_gdbm_debug_token_tyzrm = gdbm_debug_token((const char *)"r");
    if (ret_gdbm_debug_token_tyzrm < 0){
    	return 0;
    }

    int ret_variable_set_aqdmo = variable_set(ppbzbino, ret_gdbm_debug_token_tyzrm, (void *)pfp);
    if (ret_variable_set_aqdmo < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    char* ret_make_prompt_lkiak = make_prompt();
    if (ret_make_prompt_lkiak == NULL){
    	return 0;
    }

    ssize_t ret_pager_writez_kemyk = pager_writez(pfp, ret_make_prompt_lkiak);

    // End mutation: Producer.APPEND_MUTATOR

    fclose(dummy_file);

    return 0;
}