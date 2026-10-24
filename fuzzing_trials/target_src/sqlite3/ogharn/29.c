#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_29(char *fuzzData, size_t size)
{
	

   sqlite3* sqlite3_openvar1;
	memset(&sqlite3_openvar1, 0, sizeof(sqlite3_openvar1));

   unsigned int sqlite3_prepare_v3var3 = 1;
   sqlite3_stmt* sqlite3_prepare_v3var4;
	memset(&sqlite3_prepare_v3var4, 0, sizeof(sqlite3_prepare_v3var4));

   int sqlite3_os_initval1 = sqlite3_os_init();
   int sqlite3_openval1 = sqlite3_open(":memory:", &sqlite3_openvar1);
	if((int)sqlite3_openval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_openvar1){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_prepare_v3val1 = sqlite3_prepare_v3(sqlite3_openvar1, fuzzData, size, sqlite3_prepare_v3var3, &sqlite3_prepare_v3var4, &fuzzData);
	if((int)sqlite3_prepare_v3val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_prepare_v3var4){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
