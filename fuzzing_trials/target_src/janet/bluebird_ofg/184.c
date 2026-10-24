#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_184(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(0);

    // Use the input data to create a Janet string

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_table to janet_env_lookup_into
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }
    JanetTable* ret_janet_core_lookup_table_lwnks = janet_core_lookup_table(table);
    if (ret_janet_core_lookup_table_lwnks == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }
    int32_t ret_janet_abstract_decref_focyh = janet_abstract_decref((void *)table);
    if (ret_janet_abstract_decref_focyh < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_abstract_decref to janet_pretty

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_abstract_decref to janet_var
    JanetTable* ret_janet_table_weakv_nxucr = janet_table_weakv(JANET_SANDBOX_NET_CONNECT);
    if (ret_janet_table_weakv_nxucr == NULL){
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_table_weakv to janet_env_lookup_into
    JanetTable* ret_janet_table_wayhq = janet_table(JANET_LINUX);
    if (ret_janet_table_wayhq == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }
    void* ret_janet_abstract_end_threaded_jslen = janet_abstract_end_threaded(table);
    if (ret_janet_abstract_end_threaded_jslen == NULL){
    	return 0;
    }
    size_t ret_janet_os_mutex_size_bwufy = janet_os_mutex_size();
    if (ret_janet_os_mutex_size_bwufy < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_table_wayhq) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_table_weakv_nxucr) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_os_mutex_size to janet_dobytes
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_table_weakv_nxucr) {
    	return 0;
    }
    janet_table_clear(ret_janet_table_weakv_nxucr);
    JanetAtomicInt ret_janet_atomic_inc_quhzd = janet_atomic_inc(&ret_janet_abstract_decref_focyh);
    if (ret_janet_atomic_inc_quhzd < 0){
    	return 0;
    }
    void* ret_janet_smalloc_hvgnm = janet_smalloc(JANET_EV_TCTAG_STRINGF);
    if (ret_janet_smalloc_hvgnm == NULL){
    	return 0;
    }
    Janet* ret_janet_tuple_begin_klhoe = janet_tuple_begin(JANET_EV_TCTAG_BOOLEAN);
    if (ret_janet_tuple_begin_klhoe == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_table_weakv_nxucr) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_smalloc_hvgnm) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_tuple_begin_klhoe) {
    	return 0;
    }
    int ret_janet_dobytes_ymjiq = janet_dobytes(ret_janet_table_weakv_nxucr, (const uint8_t *)&ret_janet_os_mutex_size_bwufy, ret_janet_atomic_inc_quhzd, (const char *)ret_janet_smalloc_hvgnm, ret_janet_tuple_begin_klhoe);
    if (ret_janet_dobytes_ymjiq < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    janet_env_lookup_into(ret_janet_table_wayhq, ret_janet_table_weakv_nxucr, (const char *)table, (int )ret_janet_os_mutex_size_bwufy);
    // End mutation: Producer.APPEND_MUTATOR
    
    Janet ret_janet_asm_decode_instruction_gwaoo = janet_asm_decode_instruction(JANET_FILE_WRITE);
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }
    int32_t ret_janet_abstract_incref_puyvn = janet_abstract_incref((void *)table);
    if (ret_janet_abstract_incref_puyvn < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_table_weakv_nxucr) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }
    janet_var(ret_janet_table_weakv_nxucr, table, ret_janet_asm_decode_instruction_gwaoo, table);
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_var to janet_compile
    JanetFuncDef pfdxefdh;
    memset(&pfdxefdh, 0, sizeof(pfdxefdh));
    Janet ret_janet_disasm_osvim = janet_disasm(&pfdxefdh);
    uint8_t* ret_janet_string_begin_hmyco = janet_string_begin(JANET_64);
    if (ret_janet_string_begin_hmyco == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_table_weakv_nxucr) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_string_begin_hmyco) {
    	return 0;
    }
    JanetCompileResult ret_janet_compile_ncuvu = janet_compile(ret_janet_disasm_osvim, ret_janet_table_weakv_nxucr, ret_janet_string_begin_hmyco);
    // End mutation: Producer.APPEND_MUTATOR
    
    JanetBuffer fsbxlaap;
    memset(&fsbxlaap, 0, sizeof(fsbxlaap));
    janet_buffer_deinit(&fsbxlaap);
    JanetAtomicInt jttinosd = size;
    JanetAtomicInt ret_janet_atomic_inc_frnmf = janet_atomic_inc(&jttinosd);
    if (ret_janet_atomic_inc_frnmf < 0){
    	return 0;
    }
    Janet ret_janet_wrap_u64_svymz = janet_wrap_u64(JANET_SANDBOX_UNMARSHAL);
    JanetBuffer* ret_janet_pretty_qcjif = janet_pretty(&fsbxlaap, (int )ret_janet_abstract_decref_focyh, (int )ret_janet_atomic_inc_frnmf, ret_janet_wrap_u64_svymz);
    if (ret_janet_pretty_qcjif == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    int32_t ret_janet_abstract_decref_pcmlq = janet_abstract_decref((void *)table);
    if (ret_janet_abstract_decref_pcmlq < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_core_lookup_table_lwnks) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_abstract_decref to janet_optabstract
    Janet ret_janet_wrap_u64_zvicz = janet_wrap_u64((uint64_t )ret_janet_atomic_inc_quhzd);
    JanetAtomicInt ret_janet_atomic_load_relaxed_avmpe = janet_atomic_load_relaxed(&ret_janet_abstract_decref_focyh);
    if (ret_janet_atomic_load_relaxed_avmpe < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_atomic_load_relaxed to janet_resolve
    JanetTable* ret_janet_table_weakk_abnys = janet_table_weakk(1);
    if (ret_janet_table_weakk_abnys == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_abstract_end_threaded_jslen) {
    	return 0;
    }
    Janet ret_janet_resolve_core_fgyhs = janet_resolve_core((const char *)ret_janet_abstract_end_threaded_jslen);
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_table_weakk_abnys) {
    	return 0;
    }
    JanetBindingType ret_janet_resolve_sdaen = janet_resolve(ret_janet_table_weakk_abnys, (const uint8_t *)&ret_janet_atomic_load_relaxed_avmpe, &ret_janet_resolve_core_fgyhs);
    // End mutation: Producer.APPEND_MUTATOR
    
    void* ret_janet_abstract_end_threaded_vbtla = janet_abstract_end_threaded((void *)table);
    if (ret_janet_abstract_end_threaded_vbtla == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_abstract_end_threaded to janet_cstrcmp
    double ret_janet_rng_double_yzwoa = janet_rng_double(table);
    if (ret_janet_rng_double_yzwoa < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_abstract_end_threaded_vbtla) {
    	return 0;
    }
    int ret_janet_cstrcmp_sapjr = janet_cstrcmp((const uint8_t *)&ret_janet_rng_double_yzwoa, (const char *)ret_janet_abstract_end_threaded_vbtla);
    if (ret_janet_cstrcmp_sapjr < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    JanetAbstract ret_janet_optabstract_chtzd = janet_optabstract(&ret_janet_wrap_u64_zvicz, ret_janet_abstract_decref_focyh, ret_janet_abstract_decref_focyh, NULL, table);
    // End mutation: Producer.APPEND_MUTATOR
    
    janet_env_lookup_into(ret_janet_core_lookup_table_lwnks, table, table, (int )ret_janet_abstract_decref_pcmlq);
    // End mutation: Producer.APPEND_MUTATOR
    
    Janet key = janet_wrap_string(janet_string(data, size));

    // Insert the Janet string into the table with a dummy value
    janet_table_put(table, key, janet_wrap_nil());

    // Call the function-under-test
    JanetTable *result = janet_core_env(table);

    // Cleanup Janet environment

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_core_env to janet_compile_lint
    Janet ret_janet_asm_decode_instruction_borsl = janet_asm_decode_instruction(1);

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_asm_decode_instruction to janet_table_find
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_table_weakv_nxucr) {
    	return 0;
    }
    JanetTable* ret_janet_table_clone_njigf = janet_table_clone(ret_janet_table_weakv_nxucr);
    if (ret_janet_table_clone_njigf == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_table_weakv_nxucr) {
    	return 0;
    }
    JanetKV* ret_janet_table_find_exxql = janet_table_find(ret_janet_table_weakv_nxucr, ret_janet_asm_decode_instruction_gwaoo);
    if (ret_janet_table_find_exxql == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    JanetRNG tnwqadol;
    memset(&tnwqadol, 0, sizeof(tnwqadol));
    double ret_janet_rng_double_qaxqx = janet_rng_double(&tnwqadol);
    if (ret_janet_rng_double_qaxqx < 0){
    	return 0;
    }
    JanetArray* ret_janet_array_weak_sezqf = janet_array_weak(JANET_RECURSION_GUARD);
    if (ret_janet_array_weak_sezqf == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!result) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_array_weak_sezqf) {
    	return 0;
    }
    JanetCompileResult ret_janet_compile_lint_cbhna = janet_compile_lint(ret_janet_asm_decode_instruction_borsl, result, (const uint8_t *)&ret_janet_rng_double_qaxqx, ret_janet_array_weak_sezqf);
    // End mutation: Producer.APPEND_MUTATOR
    
    janet_deinit();

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_184(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
