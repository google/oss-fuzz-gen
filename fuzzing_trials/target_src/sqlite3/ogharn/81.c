#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_81(char *fuzzData, size_t size)
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
   char* sqlite3_errmsgval1 = sqlite3_errmsg(sqlite3_openvar1);
	if(!sqlite3_errmsgval1){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_enable_load_extensionval1 = sqlite3_enable_load_extension(sqlite3_openvar1, sqlite3_os_initval1);
	if((int)sqlite3_enable_load_extensionval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
