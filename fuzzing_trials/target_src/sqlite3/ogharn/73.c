#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

static void function_pointer3458764517355290624fp(void*){
	exit(0);
}
int LLVMFuzzerTestOneInput_73(char *fuzzData, size_t size)
{
	

   sqlite3* sqlite3_openvar1;
	memset(&sqlite3_openvar1, 0, sizeof(sqlite3_openvar1));

   int sqlite3_os_initval1 = sqlite3_os_init();
   int sqlite3_openval1 = sqlite3_open(":memory:", &sqlite3_openvar1);
	if((int)sqlite3_openval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_openvar1){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_open_v2val1 = sqlite3_open_v2(":memory:", &sqlite3_openvar1, size, fuzzData);
	if((int)sqlite3_open_v2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_openvar1){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_autovacuum_pagesval1 = sqlite3_autovacuum_pages(sqlite3_openvar1, NULL, (void*)fuzzData, function_pointer3458764517355290624fp);
	if((int)sqlite3_autovacuum_pagesval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
