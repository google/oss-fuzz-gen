#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_15(char *fuzzData, size_t size)
{
	

   sqlite3* sqlite3_openvar1;
	memset(&sqlite3_openvar1, 0, sizeof(sqlite3_openvar1));

   sqlite3_uint64 sqlite3_bind_text64var3;
	memset(&sqlite3_bind_text64var3, 0, sizeof(sqlite3_bind_text64var3));

   int sqlite3_os_initval1 = sqlite3_os_init();
   int sqlite3_openval1 = sqlite3_open(":memory:", &sqlite3_openvar1);
	if((int)sqlite3_openval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_openvar1){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_create_function16val1 = sqlite3_create_function16(sqlite3_openvar1, (void*)fuzzData, size, sqlite3_os_initval1, (void*)fuzzData, NULL, NULL, NULL);
	if((int)sqlite3_create_function16val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_keyword_checkval1 = sqlite3_keyword_check(fuzzData, sqlite3_create_function16val1);
	if((int)sqlite3_keyword_checkval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_bind_text64val1 = sqlite3_bind_text64(NULL, sqlite3_keyword_checkval1, fuzzData, sqlite3_bind_text64var3, NULL, *fuzzData);
	if((int)sqlite3_bind_text64val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
