#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iniparser.h"

int main(int argc, char * argv[])
{
    dictionary * ini ;
    char       * ini_name ;

    if (argc<2) {
        ini_name = "twisted.ini";
    } else {
        ini_name = argv[1] ;
    }

    ini = iniparser_load(ini_name);
    iniparser_dump(ini, stdout);
    iniparser_freedict(ini);

    return 0 ;
}
