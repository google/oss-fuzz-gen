#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_116(char *fuzzData, size_t size)
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
   int sqlite3_declare_vtabval1 = sqlite3_declare_vtab(sqlite3_openvar1, fuzzData);
	if((int)sqlite3_declare_vtabval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   sqlite3_progress_handler(NULL, sqlite3_declare_vtabval1, NULL, (void*)fuzzData);
   return 0;
}
