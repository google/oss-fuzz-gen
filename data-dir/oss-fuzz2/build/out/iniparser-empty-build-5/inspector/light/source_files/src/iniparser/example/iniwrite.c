#include "iniparser.h"

void create_empty_ini_file(void)
{
    FILE *ini;

    if ((ini = fopen("example.ini", "w")) == NULL) {
        fprintf(stderr, "iniparser: cannot create example.ini\n");
        return;
    }

    fclose(ini);
}

int write_to_ini(const char *ini_name)
{
    void *dictionary;
    FILE *ini_file;
    int ret = 0;

    if (!ini_name) {
        fprintf(stderr, "Invalid argurment\n");
        return -1;
    }

    dictionary = iniparser_load(ini_name);

    if (!dictionary) {
        fprintf(stderr, "cannot parse file: %s\n", ini_name);
        return -1;
    }

    /* set section */
    ret = iniparser_set(dictionary, "Pizza", NULL);

    if (ret < 0) {
        fprintf(stderr, "cannot set section in: %s\n", ini_name);
        ret = -1;
        goto free_dict;
    }

    /* set key/value pair */
    ret = iniparser_set(dictionary, "Pizza:Cheese", "TRUE");

    if (ret < 0) {
        fprintf(stderr, "cannot set key/value in: %s\n", ini_name);
        ret = -1;
        goto free_dict;
    }

    ini_file = fopen(ini_name, "w+");

    if (!ini_file) {
        fprintf(stderr, "iniparser: cannot create example.ini\n");
        ret = -1;
        goto free_dict;
    }

    iniparser_dump_ini(dictionary, ini_file);
    fclose(ini_file);
free_dict:
    iniparser_freedict(dictionary);
    return ret;
}

int main(int argc, char *argv[])
{
    int ret;

    if (argc < 2) {
        create_empty_ini_file();
        ret = write_to_ini("example.ini");
    } else
        ret = write_to_ini(argv[1]);

    return ret ;
}
