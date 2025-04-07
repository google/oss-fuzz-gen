#include <dirent.h>
#include <sys/stat.h>

#include <unity.h>
#include "dictionary.h"

/* We need to directly insert the .c file in order to test the */
/* static functions as well */
#include "iniparser.c"

#define GOOD_INI_PATH "ressources/good_ini"
#define BAD_INI_PATH "ressources/bad_ini"
#define OLD_INI_PATH "ressources/old.ini"
#define NEW_INI_PATH "ressources/new.ini"
#define TEST_INI_PATH "ressources/test.ini"
#define TEST_TXT_PATH "ressources/test.txt"
#define GRUEZI_INI_PATH "ressources/gruezi.ini"
#define UTF8_INI_PATH "ressources/utf8.ini"
#define TMP_INI_PATH "ressources/tmp.ini"
#define MISFORMED_INI_SEC0 "[12345"
#define MISFORMED_INI_SEC1 "12345]"
#define MISFORMED_INI_SEC2 "123]45"
#define MISFORMED_INI_ATTR "1111"
#define QUOTES_INI_PATH "ressources/quotes.ini"
#define QUOTES_INI_SEC "quotes"
#define QUOTES_INI_ATTR0 "string0"
#define QUOTES_INI_ATTR1 "string1"
#define QUOTES_INI_ATTR2 "string2"
#define QUOTES_INI_ATTR3 "string3"
#define QUOTES_INI_ATTR4 "string4"
#define QUOTES_INI_ATTR5 "string5"
#define QUOTES_INI_VAL0 "str\"ing"
#define QUOTES_INI_VAL1 "str;ing"
#define QUOTES_INI_VAL2 "str#ing"

#define stringify_2(x)     #x
#define stringify(x)       stringify_2(x)

static dictionary *dic = NULL;
static FILE *ini;
static DIR *dir;

void setUp(void)
{
}

void tearDown(void)
{
    if(dic)
        dictionary_del(dic);
    dic = NULL;
    if(ini)
        fclose(ini);
    ini = NULL;
    if(dir)
        closedir(dir);
    dir = NULL;
}

/* Tool function to create and populate a generic non-empty dictionary */
static dictionary * generate_dictionary(unsigned sections, unsigned entries_per_section)
{
    unsigned i, j ;
    dictionary * dic;
    char sec_name[32];
    char key_name[64];
    char key_value[32];

    dic = dictionary_new(sections + sections * entries_per_section);
    if (dic == NULL)
        return NULL;

    /* Insert the sections */
    for (i = 0; i < sections; ++i) {
        sprintf(sec_name, "sec%d", i);
        dictionary_set(dic, sec_name, "");
        for (j = 0; j < entries_per_section; ++j) {
            /* Populate the section with the entries */
            sprintf(key_name, "%s:key%d", sec_name, j);
            sprintf(key_value, "value-%d/%d", i, j);
            dictionary_set(dic, key_name, key_value);
        }
    }

    return dic;
}

void test_iniparser_strlwc(void)
{
    char out_buffer[128];

    /* NULL ptr as input */
    TEST_ASSERT_NULL(strlwc(NULL, NULL, 0));
    TEST_ASSERT_NULL(strlwc(NULL, out_buffer, sizeof (out_buffer)));
    TEST_ASSERT_NULL(strlwc("", NULL, sizeof (out_buffer)));
    TEST_ASSERT_NULL(strlwc("", out_buffer, 0));
    TEST_ASSERT_NULL(strlwc(NULL, NULL, 0));

    /* empty string */
    TEST_ASSERT_EQUAL_STRING("", strlwc("", out_buffer, sizeof (out_buffer)));
    TEST_ASSERT_EQUAL_STRING("  ",
                             strlwc("  ", out_buffer, sizeof (out_buffer)));
    TEST_ASSERT_EQUAL_STRING("test",
                             strlwc("test", out_buffer, sizeof (out_buffer)));
    TEST_ASSERT_EQUAL_STRING("test",
                             strlwc("TEST", out_buffer, sizeof (out_buffer)));
    TEST_ASSERT_EQUAL_STRING("test",
                             strlwc("TeSt", out_buffer, sizeof (out_buffer)));
    TEST_ASSERT_EQUAL_STRING("test test",
                             strlwc("TEST TEST", out_buffer,
                                    sizeof (out_buffer)));
    TEST_ASSERT_EQUAL_STRING("very long string !!!!!!!",
                             strlwc("very long string !!!!!!!", out_buffer,
                                    sizeof (out_buffer)));
    TEST_ASSERT_EQUAL_STRING("cutted string",
                             strlwc("cutted string<---here", out_buffer, 14));

    /* test using same buffer as input and output */
    strcpy(out_buffer, "OVERWRITE ME !");
    TEST_ASSERT_NOT_NULL(strlwc(out_buffer, out_buffer, sizeof(out_buffer)));
    TEST_ASSERT_EQUAL_STRING("overwrite me !", out_buffer);
}

void test_iniparser_strstrip(void)
{
    /* First element in the array is the expected stripping result */
    const char *strings_empty[] = {
        "",
        "       ",
        "\n\n\n\n",
        "\t\t\t\t",
        "\n     \t\n\t\n    "
    };
    const char *strings_test[] = {
        "test",
        "test ",
        "test          ",
        " test",
        "   test    ",
        "\ttest\t",
        "\ttest\n"

    };
    const char *test_with_spaces = "I am a test with\tspaces.";
    char stripped[ASCIILINESZ+1];
    char error_msg[1060];
    unsigned i;

    /* NULL ptr as input */
    strstrip(NULL);

    /* empty string */
    for (i = 0 ; i < sizeof (strings_empty) / sizeof (char *) ; ++i) {
        strcpy(stripped, strings_empty[i]);
        strstrip(stripped);
        sprintf(error_msg, "Bad stripping : strstrip(\"%s\") ==> \"%s\"",
                strings_empty[i], stripped);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(stripped, strings_empty[0], error_msg);
    }

    /* test string */
    for (i = 0 ; i < sizeof (strings_test) / sizeof (char *) ; ++i) {
        strcpy(stripped, strings_test[i]);
        strstrip(stripped);
        sprintf(error_msg, "Bad stripping : strstrip(\"%s\") ==> \"%s\"",
                strings_test[i], stripped);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(strings_test[0], stripped, error_msg);
    }
    strcpy(stripped, ".");
    strstrip(stripped);
    TEST_ASSERT_EQUAL_STRING(".", stripped);

    /* string containing spaces */
    strcpy(stripped, test_with_spaces);
    strstrip(stripped);
    TEST_ASSERT_EQUAL_STRING(test_with_spaces, stripped);
}

void test_iniparser_getnsec(void)
{
    int i;
    char sec_name[32];

    /* NULL test */
    TEST_ASSERT_EQUAL(-1, iniparser_getnsec(NULL));

    /* Empty dictionary */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_EQUAL(0, iniparser_getnsec(dic));
    dictionary_del(dic);
    dic = NULL;

    /* Regular dictionary */
    dic = generate_dictionary(512, 0);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_EQUAL(512, iniparser_getnsec(dic));

    /* Check after removing sections */
    for (i = 1; i < 512; ++i) {
        sprintf(sec_name, "sec%d", i);
        dictionary_unset(dic, sec_name);
        TEST_ASSERT_EQUAL(512 - i, iniparser_getnsec(dic));
    }
    dictionary_del(dic);
    dic = NULL;

    /* Mix sections and regular keys */
    dic = generate_dictionary(10, 512);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_EQUAL(10, iniparser_getnsec(dic));
    dictionary_del(dic);
    dic = NULL;
}

void test_iniparser_getsecname(void)
{
    unsigned i;
    char sec_name[32];
    /* NULL test */
    TEST_ASSERT_NULL(iniparser_getsecname(NULL, 0));

    /* Empty dictionary */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_NULL(iniparser_getsecname(dic, 0));
    dictionary_del(dic);
    dic = NULL;

    /* Sections without entries dictionary */
    dic = generate_dictionary(100, 0);
    TEST_ASSERT_NOT_NULL(dic);
    for (i = 0; i < 100; ++i) {
        sprintf(sec_name, "sec%d", i);
        TEST_ASSERT_EQUAL_STRING(sec_name, iniparser_getsecname(dic, i));
    }
    dictionary_del(dic);
    dic = NULL;

    /* Generic dictionary */
    dic = generate_dictionary(10, 100);
    TEST_ASSERT_NOT_NULL(dic);
    for (i = 0; i < 10; ++i) {
        sprintf(sec_name, "sec%d", i);
        TEST_ASSERT_EQUAL_STRING(sec_name, iniparser_getsecname(dic, i));
    }
    dictionary_del(dic);
    dic = NULL;
}

void test_iniparser_getseckeys(void)
{
    unsigned i;
    char key_name[64];
    int nkeys;
    const char * keys[10]; /* At most 10 elements per section */
    /* NULL test */
    TEST_ASSERT_NULL(iniparser_getseckeys(NULL, NULL, NULL));
    TEST_ASSERT_NULL(iniparser_getseckeys(NULL, "dummy", NULL));
    TEST_ASSERT_NULL(iniparser_getseckeys(NULL, "dummy", keys));

    /* Empty dictionary */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_NULL(iniparser_getseckeys(dic, NULL, keys));
    TEST_ASSERT_NULL(iniparser_getseckeys(dic, "dummy", keys));
    dictionary_del(dic);
    dic = NULL;

    /* Generic dictionary */

    dic = generate_dictionary(100, 10);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_NULL(iniparser_getseckeys(dic, NULL, keys));
    TEST_ASSERT_NULL(iniparser_getseckeys(dic, "dummy", keys));
    TEST_ASSERT_NULL(iniparser_getseckeys(dic, "sec0", NULL));
    nkeys = iniparser_getsecnkeys(dic, "sec42");
    TEST_ASSERT_EQUAL(nkeys, 10);
    TEST_ASSERT_EQUAL_STRING(keys, iniparser_getseckeys(dic, "sec42", keys));
    for (i = 0; i < 10; ++i) {
        sprintf(key_name, "sec42:key%d", i);
        TEST_ASSERT_EQUAL_STRING(key_name, keys[i]);
    }

    /* Remove some keys to make the dictionary more real */
    dictionary_unset(dic, "sec42");
    dictionary_unset(dic, "sec99:key9");
    dictionary_unset(dic, "sec0:key0");
    dictionary_unset(dic, "sec0:key1");
    dictionary_unset(dic, "sec0:key2");

    TEST_ASSERT_NULL(iniparser_getseckeys(dic, "sec42", keys));
    nkeys = iniparser_getsecnkeys(dic, "Sec99");
    TEST_ASSERT_EQUAL(nkeys, 9);
    TEST_ASSERT_EQUAL_STRING(keys, iniparser_getseckeys(dic, "Sec99", keys));
    for (i = 0; i < 9; ++i) {
        sprintf(key_name, "sec99:key%d", i);
        TEST_ASSERT_EQUAL_STRING(key_name, keys[i]);
    }

    nkeys = iniparser_getsecnkeys(dic, "sec0");
    TEST_ASSERT_EQUAL(nkeys, 7);
    TEST_ASSERT_EQUAL_STRING(keys, iniparser_getseckeys(dic, "sec0", keys));
    for (i = 0; i < 7; ++i) {
        sprintf(key_name, "sec0:key%d", i + 3);
        TEST_ASSERT_EQUAL_STRING(key_name, keys[i]);
    }

    dictionary_del(dic);
    dic = NULL;
}

void test_iniparser_getstring(void)
{
    /* NULL test */
    TEST_ASSERT_NULL(iniparser_getstring(NULL, NULL, NULL));
    TEST_ASSERT_NULL(iniparser_getstring(NULL, "dummy", NULL));

    /* Check the def return element */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_NULL(iniparser_getstring(dic, "dummy", NULL));
    TEST_ASSERT_EQUAL_STRING("def", iniparser_getstring(dic, NULL, "def"));
    TEST_ASSERT_EQUAL_STRING("def", iniparser_getstring(dic, "dummy", "def"));
    dictionary_del(dic);
    dic = NULL;

    /* Generic dictionary */
    dic = generate_dictionary(100, 10);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_EQUAL_STRING("value-0/0",
                             iniparser_getstring(dic, "sec0:key0", NULL));
    TEST_ASSERT_EQUAL_STRING("value-42/5",
                             iniparser_getstring(dic, "sec42:key5", NULL));
    TEST_ASSERT_EQUAL_STRING("value-99/9",
                             iniparser_getstring(dic, "sec99:key9", NULL));
    dictionary_del(dic);
    dic = NULL;
}

void test_iniparser_getint(void)
{
    unsigned i;
    char key_name[64];
    const struct {
        int num;
        const char *value;
    } good_val[] = {
        { 0, "0" },
        { 1, "1" },
        { -1, "-1" },
        { 1000, "1000" },
        { 077, "077" },
        { -01000, "-01000" },
        { 0xFFFF, "0xFFFF" },
        { -0xFFFF, "-0xFFFF" },
        { 0x4242, "0x4242" },
        { 0, NULL} /* must be last */
    };
    const char *bad_val[] = {
        "",
        "notanumber",
        "0x",
        "k2000",
        " ",
        "0xG1"
    };
    /* NULL test */
    TEST_ASSERT_EQUAL(-42, iniparser_getint(NULL, NULL, -42));
    TEST_ASSERT_EQUAL(-42, iniparser_getint(NULL, "dummy", -42));

    /* Check the def return element */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_EQUAL(42, iniparser_getint(dic, "dummy", 42));
    TEST_ASSERT_EQUAL_HEX(0xFFFF, iniparser_getint(dic, NULL, 0xFFFF));
    TEST_ASSERT_EQUAL_HEX(-0xFFFF, iniparser_getint(dic, "dummy", -0xFFFF));
    dictionary_del(dic);
    dic = NULL;

    /* Generic dictionary */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    for (i = 0; good_val[i].value != NULL; ++i) {
        sprintf(key_name, "int:value%d", i);
        dictionary_set(dic, key_name, good_val[i].value);
    }
    for (i = 0; good_val[i].value != NULL; ++i) {
        sprintf(key_name, "int:value%d", i);
        TEST_ASSERT_EQUAL(good_val[i].num,
                          iniparser_getint(dic, key_name, 0));
    }
    dictionary_del(dic);
    dic = NULL;

    /* Test bad names */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    for (i = 0; i < sizeof (bad_val) / sizeof (char *); ++i) {
        sprintf(key_name, "int:bad%d", i);
        dictionary_set(dic, key_name, bad_val[i]);
    }
    for (i = 0; i < sizeof (bad_val) / sizeof (char *); ++i) {
        sprintf(key_name, "int:bad%d", i);
        TEST_ASSERT_EQUAL(0,
                          iniparser_getint(dic, key_name, 0));
    }
    dictionary_del(dic);
    dic = NULL;
}

void test_iniparser_getlongint(void)
{
    unsigned i;
    char key_name[64];
    const struct {
        long int num;
        const char *value;
    } good_val[] = {
        { 0, "0" },
        { 1, "1" },
        { -1, "-1" },
        { 1000, "1000" },
        { 077, "077" },
        { -01000, "-01000" },
        { LONG_MAX, stringify(LONG_MAX) },
        { -LONG_MAX, stringify(-LONG_MAX) },
        { 0x4242, "0x4242" },
        { 0, NULL} /* must be last */
    };
    const char *bad_val[] = {
        "",
        "notanumber",
        "0x",
        "k2000",
        " ",
        "0xG1"
    };
    /* NULL test */
    TEST_ASSERT_EQUAL(-42, iniparser_getlongint(NULL, NULL, -42));
    TEST_ASSERT_EQUAL(-42, iniparser_getlongint(NULL, "dummy", -42));

    /* Check the def return element */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_EQUAL(42, iniparser_getlongint(dic, "dummy", 42));
    TEST_ASSERT_EQUAL(LONG_MAX, iniparser_getlongint(dic, NULL, LONG_MAX));
    TEST_ASSERT_EQUAL(-LONG_MAX, iniparser_getlongint(dic, "dummy", -LONG_MAX));
    dictionary_del(dic);
    dic = NULL;

    /* Generic dictionary */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    for (i = 0; good_val[i].value != NULL; ++i) {
        sprintf(key_name, "longint:value%d", i);
        dictionary_set(dic, key_name, good_val[i].value);
    }
    for (i = 0; good_val[i].value != NULL; ++i) {
        sprintf(key_name, "longint:value%d", i);
        TEST_ASSERT_EQUAL(good_val[i].num,
                          iniparser_getlongint(dic, key_name, 0));
    }
    dictionary_del(dic);
    dic = NULL;

    /* Test bad names */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    for (i = 0; i < sizeof (bad_val) / sizeof (char *); ++i) {
        sprintf(key_name, "longint:bad%d", i);
        dictionary_set(dic, key_name, bad_val[i]);
    }
    for (i = 0; i < sizeof (bad_val) / sizeof (char *); ++i) {
        sprintf(key_name, "longint:bad%d", i);
        TEST_ASSERT_EQUAL(0,
                          iniparser_getlongint(dic, key_name, 0));
    }
    dictionary_del(dic);
    dic = NULL;
}

void test_iniparser_getint64(void)
{
    unsigned i;
    char key_name[64];
    const struct {
        int64_t num;
        const char *value;
    } good_val[] = {
        { 0, "0" },
        { 1, "1" },
        { -1, "-1" },
        { 1000, "1000" },
        { 077, "077" },
        { -01000, "-01000" },
        { 0x7FFFFFFFFFFFFFFF, "0x7FFFFFFFFFFFFFFF" },
        { -0x7FFFFFFFFFFFFFFF, "-0x7FFFFFFFFFFFFFFF" },
        { 0x4242, "0x4242" },
        { 0, NULL} /* must be last */
    };
    const char *bad_val[] = {
        "",
        "notanumber",
        "0x",
        "k2000",
        " ",
        "0xG1"
    };
    /* NULL test */
    TEST_ASSERT_EQUAL_INT64(-42, iniparser_getint64(NULL, NULL, -42));
    TEST_ASSERT_EQUAL_INT64(-42, iniparser_getint64(NULL, "dummy", -42));

    /* Check the def return element */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_EQUAL_INT64(42, iniparser_getint64(dic, "dummy", 42));
    TEST_ASSERT_EQUAL_HEX64(0x7FFFFFFFFFFFFFFF,
                            iniparser_getint64(dic, NULL, 0x7FFFFFFFFFFFFFFF));
    TEST_ASSERT_EQUAL_HEX64(-0x7FFFFFFFFFFFFFFF,
                            iniparser_getint64(dic, "dummy",
                                -0x7FFFFFFFFFFFFFFF));
    dictionary_del(dic);
    dic = NULL;

    /* Generic dictionary */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    for (i = 0; good_val[i].value != NULL; ++i) {
        sprintf(key_name, "longint:value%d", i);
        dictionary_set(dic, key_name, good_val[i].value);
    }
    for (i = 0; good_val[i].value != NULL; ++i) {
        sprintf(key_name, "longint:value%d", i);
        TEST_ASSERT_EQUAL_INT64(good_val[i].num,
                                iniparser_getint64(dic, key_name, 0));
    }
    dictionary_del(dic);
    dic = NULL;

    /* Test bad names */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    for (i = 0; i < sizeof (bad_val) / sizeof (char *); ++i) {
        sprintf(key_name, "longint:bad%d", i);
        dictionary_set(dic, key_name, bad_val[i]);
    }
    for (i = 0; i < sizeof (bad_val) / sizeof (char *); ++i) {
        sprintf(key_name, "longint:bad%d", i);
        TEST_ASSERT_EQUAL_INT64(0,
                                iniparser_getint64(dic, key_name, 0));
    }
    dictionary_del(dic);
    dic = NULL;
}

void test_iniparser_getuint64(void)
{
    unsigned i;
    char key_name[64];
    const struct {
        uint64_t num;
        const char *value;
    } good_val[] = {
        { 0, "0" },
        { 1, "1" },
        { -1, "-1" },
        { 1000, "1000" },
        { 077, "077" },
        { -01000, "-01000" },
        { 0xFFFFFFFFFFFFFFFF, "0xFFFFFFFFFFFFFFFF" },
        { -0xFFFFFFFFFFFFFFFF, "-0xFFFFFFFFFFFFFFFF" },
        { 0x4242, "0x4242" },
        { 0, NULL} /* must be last */
    };
    const char *bad_val[] = {
        "",
        "notanumber",
        "0x",
        "k2000",
        " ",
        "0xG1"
    };
    /* NULL test */
    TEST_ASSERT_EQUAL_UINT64(-42, iniparser_getuint64(NULL, NULL, -42));
    TEST_ASSERT_EQUAL_UINT64(-42, iniparser_getuint64(NULL, "dummy", -42));

    /* Check the def return element */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_EQUAL_UINT64(42, iniparser_getuint64(dic, "dummy", 42));
    TEST_ASSERT_EQUAL_HEX64(0xFFFFFFFFFFFFFFFF,
                            iniparser_getuint64(dic, NULL, 0xFFFFFFFFFFFFFFFF));
    TEST_ASSERT_EQUAL_HEX64(-0xFFFFFFFFFFFFFFFF,
                            iniparser_getuint64(dic, "dummy",
                                -0xFFFFFFFFFFFFFFFF));
    dictionary_del(dic);
    dic = NULL;

    /* Generic dictionary */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    for (i = 0; good_val[i].value != NULL; ++i) {
        sprintf(key_name, "longint:value%d", i);
        dictionary_set(dic, key_name, good_val[i].value);
    }
    for (i = 0; good_val[i].value != NULL; ++i) {
        sprintf(key_name, "longint:value%d", i);
        TEST_ASSERT_EQUAL_UINT64(good_val[i].num,
                                 iniparser_getuint64(dic, key_name, 0));
    }
    dictionary_del(dic);
    dic = NULL;

    /* Test bad names */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    for (i = 0; i < sizeof (bad_val) / sizeof (char *); ++i) {
        sprintf(key_name, "longint:bad%d", i);
        dictionary_set(dic, key_name, bad_val[i]);
    }
    for (i = 0; i < sizeof (bad_val) / sizeof (char *); ++i) {
        sprintf(key_name, "longint:bad%d", i);
        TEST_ASSERT_EQUAL_UINT64(0,
                                 iniparser_getuint64(dic, key_name, 0));
    }
    dictionary_del(dic);
    dic = NULL;
}

void test_iniparser_getdouble(void)
{

    /* NULL test */
    TEST_ASSERT_EQUAL_DOUBLE(-42, iniparser_getdouble(NULL, NULL, -42));
    TEST_ASSERT_EQUAL_DOUBLE(4.2, iniparser_getdouble(NULL, "dummy", 4.2));

    /* Check the def return element */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_EQUAL_DOUBLE(3.1415,
                             iniparser_getdouble(dic, "dummy", 3.1415));
    TEST_ASSERT_EQUAL_DOUBLE(0xFFFFFFFF,
                             iniparser_getdouble(dic, NULL, 0xFFFFFFFF));
    TEST_ASSERT_EQUAL_DOUBLE(-0xFFFFFFFF,
                             iniparser_getdouble(dic, "dummy", -0xFFFFFFFF));

    /* Insert some values */
    dictionary_set(dic, "double", "");
    dictionary_set(dic, "double:good0", "0");
    dictionary_set(dic, "double:good1", "-0");
    dictionary_set(dic, "double:good2", "1.0");
    dictionary_set(dic, "double:good3", "3.1415");
    dictionary_set(dic, "double:good4", "6.6655957");
    dictionary_set(dic, "double:good5", "-123456789.123456789");

    /* Add dummy stuff too */
    dictionary_set(dic, "double:bad0", "foo");

    /* Get back the values */
    TEST_ASSERT_EQUAL_DOUBLE(0, iniparser_getdouble(dic, "double:good0", 0xFF));
    TEST_ASSERT_EQUAL_DOUBLE(0, iniparser_getdouble(dic, "double:good1", 0xFF));
    TEST_ASSERT_EQUAL_DOUBLE(1.0,
                             iniparser_getdouble(dic, "double:good2", 0xFF));
    TEST_ASSERT_EQUAL_DOUBLE(3.1415,
                             iniparser_getdouble(dic, "double:good3", 0xFF));
    TEST_ASSERT_EQUAL_DOUBLE(6.6655957,
                             iniparser_getdouble(dic, "double:good4", 0xFF));
    TEST_ASSERT_EQUAL_DOUBLE(-123456789.123456789,
                             iniparser_getdouble(dic, "double:good5", 0xFF));

    TEST_ASSERT_EQUAL_DOUBLE(0, iniparser_getdouble(dic, "double:bad0", 42.42));

    dictionary_del(dic);
    dic = NULL;
}

void test_iniparser_getboolean(void)
{
    unsigned i;
    char key_name[64];

    const char *token_true[] = {
        "1",
        "true",
        "t",
        "TRUE",
        "T",
        "yes",
        "y",
        "YES",
        "Y",
        NULL
    };
    const char *token_false[] = {
        "0",
        "false",
        "f",
        "FALSE",
        "F",
        "no",
        "n",
        "NO",
        "N",
        NULL
    };

    /* NULL test */
    TEST_ASSERT_EQUAL(1, iniparser_getboolean(NULL, NULL, 1));
    TEST_ASSERT_EQUAL(1, iniparser_getboolean(NULL, "dummy", 1));

    /* Check the def return element */
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_EQUAL(1, iniparser_getboolean(dic, "dummy", 1));
    TEST_ASSERT_EQUAL(0, iniparser_getboolean(dic, NULL, 0));
    TEST_ASSERT_EQUAL(1, iniparser_getboolean(dic, "dummy", 1));

    for (i = 0; token_true[i] != NULL; ++i) {
        sprintf(key_name, "bool:true%d", i);
        iniparser_set(dic, key_name, token_true[i]);
    }
    for (i = 0; token_false[i] != NULL; ++i) {
        sprintf(key_name, "bool:false%d", i);
        iniparser_set(dic, key_name, token_false[i]);
    }

    for (i = 0; token_true[i] != NULL; ++i) {
        sprintf(key_name, "bool:true%d", i);
        TEST_ASSERT_EQUAL(1, iniparser_getboolean(dic, key_name, 0));
    }
    for (i = 0; token_false[i] != NULL; ++i) {
        sprintf(key_name, "bool:false%d", i);
        TEST_ASSERT_EQUAL(0, iniparser_getboolean(dic, key_name, 1));
    }

    /* Test bad boolean */
    iniparser_set(dic, "bool:bad0", "");
    iniparser_set(dic, "bool:bad1", "m'kay");
    iniparser_set(dic, "bool:bad2", "42");
    iniparser_set(dic, "bool:bad3", "_true");
    TEST_ASSERT_EQUAL_HEX(0xFF, iniparser_getboolean(dic, "bool:bad0", 0xFF));
    TEST_ASSERT_EQUAL_HEX(0xFF, iniparser_getboolean(dic, "bool:bad1", 0xFF));
    TEST_ASSERT_EQUAL_HEX(0xFF, iniparser_getboolean(dic, "bool:bad2", 0xFF));
    TEST_ASSERT_EQUAL_HEX(0xFF, iniparser_getboolean(dic, "bool:bad3", 0xFF));

    dictionary_del(dic);
    dic = NULL;
}

void test_iniparser_line(void)
{
    char section [ASCIILINESZ+1] ;
    char key     [ASCIILINESZ+1] ;
    char val     [ASCIILINESZ+1] ;

    /* Test empty line */
    TEST_ASSERT_EQUAL(LINE_EMPTY, iniparser_line("", section, key, val));
    TEST_ASSERT_EQUAL(LINE_EMPTY, iniparser_line("    ", section, key, val));
    TEST_ASSERT_EQUAL(LINE_EMPTY, iniparser_line("\t", section, key, val));

    /* Test valid syntax */
    TEST_ASSERT_EQUAL(LINE_SECTION, iniparser_line("[s]", section, key, val));
    TEST_ASSERT_EQUAL_STRING("s", section);

    TEST_ASSERT_EQUAL(LINE_SECTION, iniparser_line("[section 0]", section, key, val));
    TEST_ASSERT_EQUAL_STRING("section 0", section);

    TEST_ASSERT_EQUAL(LINE_SECTION, iniparser_line("[ section 0 ]", section, key, val));
    TEST_ASSERT_EQUAL_STRING("section 0", section);

    TEST_ASSERT_EQUAL(LINE_SECTION, iniparser_line("[ section ]", section, key, val));
    TEST_ASSERT_EQUAL_STRING("section", section);

    TEST_ASSERT_EQUAL(LINE_VALUE, iniparser_line("k=1", section, key, val));
    TEST_ASSERT_EQUAL_STRING("k", key);
    TEST_ASSERT_EQUAL_STRING("1", val);

    TEST_ASSERT_EQUAL(LINE_VALUE, iniparser_line("key = 0x42", section, key, val));
    TEST_ASSERT_EQUAL_STRING("key", key);
    TEST_ASSERT_EQUAL_STRING("0x42", val);

    TEST_ASSERT_EQUAL(LINE_VALUE, iniparser_line("key= value with spaces", section, key, val));
    TEST_ASSERT_EQUAL_STRING("key", key);
    TEST_ASSERT_EQUAL_STRING("value with spaces", val);

    TEST_ASSERT_EQUAL(LINE_VALUE, iniparser_line("k =_!<>''", section, key, val));
    TEST_ASSERT_EQUAL_STRING("k", key);
    TEST_ASSERT_EQUAL_STRING("_!<>''", val);

    TEST_ASSERT_EQUAL(LINE_VALUE, iniparser_line("empty_value =", section, key, val));
    TEST_ASSERT_EQUAL_STRING("empty_value", key);
    TEST_ASSERT_EQUAL_STRING("", val);

    TEST_ASSERT_EQUAL(LINE_VALUE, iniparser_line("empty_value =        \t\n", section, key, val));
    TEST_ASSERT_EQUAL_STRING("empty_value", key);
    TEST_ASSERT_EQUAL_STRING("", val);

    TEST_ASSERT_EQUAL(LINE_VALUE, iniparser_line("key =\tval # comment", section, key, val));
    TEST_ASSERT_EQUAL_STRING("key", key);
    TEST_ASSERT_EQUAL_STRING("val", val);

    TEST_ASSERT_EQUAL(LINE_VALUE, iniparser_line("key \n\n = \n val", section, key, val));
    TEST_ASSERT_EQUAL_STRING("key", key);
    TEST_ASSERT_EQUAL_STRING("val", val);

    TEST_ASSERT_EQUAL(LINE_COMMENT, iniparser_line(";comment", section, key, val));
    TEST_ASSERT_EQUAL(LINE_COMMENT, iniparser_line(" # comment", section, key, val));

    TEST_ASSERT_EQUAL(LINE_VALUE, iniparser_line("key = \"  do_not_strip  \"", section, key, val));
    TEST_ASSERT_EQUAL_STRING("key", key);
    TEST_ASSERT_EQUAL_STRING("  do_not_strip  ", val);

    TEST_ASSERT_EQUAL(LINE_VALUE, iniparser_line("key = '    '", section, key, val));
    TEST_ASSERT_EQUAL_STRING("key", key);
    TEST_ASSERT_EQUAL_STRING("    ", val);

    TEST_ASSERT_EQUAL(LINE_VALUE, iniparser_line("key = \"\"", section, key, val));
    TEST_ASSERT_EQUAL_STRING("key", key);
    TEST_ASSERT_EQUAL_STRING("", val);

    TEST_ASSERT_EQUAL(LINE_VALUE, iniparser_line("key = ''", section, key, val));
    TEST_ASSERT_EQUAL_STRING("key", key);
    TEST_ASSERT_EQUAL_STRING("", val);

    /* Test syntax error */
    TEST_ASSERT_EQUAL(LINE_ERROR, iniparser_line("empty_value", section, key, val));
    TEST_ASSERT_EQUAL(LINE_ERROR, iniparser_line("not finished\\", section, key, val));
    TEST_ASSERT_EQUAL(LINE_ERROR, iniparser_line("0x42 / 0b101010", section, key, val));

}

void test_iniparser_load(void)
{
    struct dirent *curr;
    struct stat curr_stat;
    char ini_path[276];

    /* Dummy tests */
    dic = iniparser_load("/you/shall/not/path");
    TEST_ASSERT_NULL(dic);

    /* Test all the good .ini files */
    dir = opendir(GOOD_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dir, "cannot open " GOOD_INI_PATH);
    for (curr = readdir(dir); curr != NULL; curr = readdir(dir)) {
        sprintf(ini_path, "%s/%s", GOOD_INI_PATH, curr->d_name);
        stat(ini_path, &curr_stat);
        if (S_ISREG(curr_stat.st_mode)) {
            dic = iniparser_load(ini_path);
            TEST_ASSERT_NOT_NULL_MESSAGE(dic, ini_path);
            dictionary_del(dic);
            dic = NULL;
        }
    }
    closedir(dir);
    dir = NULL;

    /* Test all the bad .ini files */
    dir = opendir(BAD_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dir, "cannot open " BAD_INI_PATH);
    for (curr = readdir(dir); curr != NULL; curr = readdir(dir)) {
        sprintf(ini_path, "%s/%s", BAD_INI_PATH, curr->d_name);
        stat(ini_path, &curr_stat);
        if (S_ISREG(curr_stat.st_mode)) {
            dic = iniparser_load(ini_path);
            TEST_ASSERT_EQUAL_PTR_MESSAGE(NULL, dic, ini_path);
            dictionary_del(dic);
            dic = NULL;
        }
    }
    closedir(dir);
    dir = NULL;
}

void test_dictionary_wrapper(void)
{
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);

    TEST_ASSERT_EQUAL(-1, iniparser_set(dic, NULL, NULL));
    TEST_ASSERT_EQUAL(-1, iniparser_set(NULL, "section", "value"));

    TEST_ASSERT_EQUAL(0, iniparser_set(dic, "section", NULL));
    TEST_ASSERT_EQUAL(0, iniparser_set(dic, "section:key", "value"));

    TEST_ASSERT_EQUAL_STRING("value", iniparser_getstring(dic, "section:key", NULL));
    /* reset the key's value*/
    TEST_ASSERT_EQUAL(0, iniparser_set(dic, "section:key", NULL));
    TEST_ASSERT_NULL(iniparser_getstring(dic, "section:key", "dummy"));
    TEST_ASSERT_EQUAL(0, iniparser_set(dic, "section:key", "value"));
    TEST_ASSERT_EQUAL_STRING("value", iniparser_getstring(dic, "section:key", NULL));

    iniparser_unset(dic, "section:key");
    TEST_ASSERT_EQUAL_STRING("dummy", iniparser_getstring(dic, "section:key", "dummy"));
    TEST_ASSERT_NULL(iniparser_getstring(dic, "section", "dummy"));

    TEST_ASSERT_EQUAL(0, iniparser_set(dic, "section:key", NULL));
    TEST_ASSERT_EQUAL(0, iniparser_set(dic, "section:key1", NULL));
    TEST_ASSERT_EQUAL(0, iniparser_set(dic, "section:key2", NULL));

    iniparser_unset(dic, "section");
    TEST_ASSERT_NULL(iniparser_getstring(dic, "section", NULL));

    iniparser_freedict(dic);
    dic = NULL;
}

static char _last_error[1024];
static int _error_callback(const char *format, ...)
{
    int ret;
    va_list argptr;
    va_start(argptr, format);
    ret = vsprintf(_last_error, format, argptr);
    va_end(argptr);
    return ret;

}

void test_iniparser_error_callback(void)
{
    /* Specify our custom error_callback */
    iniparser_set_error_callback(_error_callback);

    /* Trigger an error and check it was written on the right output */
    dic = iniparser_load("/path/to/nowhere.ini");
    TEST_ASSERT_NULL(dic);
    TEST_ASSERT_EQUAL_STRING("iniparser: cannot open /path/to/nowhere.ini\n",
                             _last_error);

    /* Reset erro_callback */
    _last_error[0] = '\0';
    iniparser_set_error_callback(NULL);

    /* Make sure custom callback is no more called */
    dic = iniparser_load("/path/to/nowhere.ini");
    TEST_ASSERT_NULL(dic);
    TEST_ASSERT_EQUAL_STRING("", _last_error);
}

void test_iniparser_dump(void)
{
    char buff[255];
    const char *str;

    /*loading old.ini*/
    dic = iniparser_load(OLD_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " OLD_INI_PATH);
    /*check the data of old.ini*/
    str = iniparser_getstring(dic,"section:key_01",NULL);
    TEST_ASSERT_EQUAL_STRING("hello world", str);
    str = iniparser_getstring(dic,"section:key1",NULL);
    TEST_ASSERT_EQUAL_STRING("321abc", str);
    /*open test.txt*/
    ini = fopen(TEST_TXT_PATH,"w");
    TEST_ASSERT_NOT_NULL_MESSAGE(ini, "cannot open " TEST_TXT_PATH);
    /*dump the data of old.ini to new.ini*/
    iniparser_dump(dic,ini);
    fclose(ini);
    ini = NULL;
    iniparser_freedict(dic);
    dic = NULL;
    /*read the data of test.txt*/
    ini = fopen(TEST_TXT_PATH,"r");
    TEST_ASSERT_NOT_NULL_MESSAGE(ini, "cannot open " TEST_TXT_PATH);
    str = fgets(buff,100,ini);
    (void)str;
    /*remove '\n'*/
    if(buff[strlen(buff)-1] == '\n')
    {
        buff[strlen(buff)-1] = '\0';
    }
    TEST_ASSERT_EQUAL_STRING("[section]=UNDEF",buff);
    str = fgets(buff,100,ini);
    (void)str;
    if(buff[strlen(buff)-1] == '\n')
    {
        buff[strlen(buff)-1] = '\0';
    }
    TEST_ASSERT_EQUAL_STRING("[section:key_01]=[hello world]",buff);
    str = fgets(buff,100,ini);
    (void)str;
    if(buff[strlen(buff)-1] == '\n')
    {
        buff[strlen(buff)-1] = '\0';
    }
    TEST_ASSERT_EQUAL_STRING("[section:key1]=[321abc]",buff);
    fclose(ini);
    ini = NULL;
}

void test_iniparser_dump_ini(void)
{
    const char *str;
    char val[4096] = {};
    int ret;

    /*loading old.ini*/
    dic = iniparser_load(OLD_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " OLD_INI_PATH);
    /*check the data of old.ini*/
    str = iniparser_getstring(dic,"section:key_01",NULL);
    TEST_ASSERT_EQUAL_STRING("hello world", str);
    str = iniparser_getstring(dic,"section:key1",NULL);
    TEST_ASSERT_EQUAL_STRING("321abc", str);
    /*open new.ini*/
    ini = fopen(NEW_INI_PATH,"w");
    TEST_ASSERT_NOT_NULL_MESSAGE(ini, "cannot open " NEW_INI_PATH);
    /*dump the data of old.ini to new.ini*/
    iniparser_dump_ini(dic,ini);
    fclose(ini);
    ini = NULL;
    iniparser_freedict(dic);
    dic = NULL;
    /*loading new.ini*/
    dic = iniparser_load(NEW_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " NEW_INI_PATH);
    /*check the data of new.ini*/
    str = iniparser_getstring(dic,"section:key_01",NULL);
    TEST_ASSERT_EQUAL_STRING("hello world", str);
    str = iniparser_getstring(dic,"section:key1",NULL);
    TEST_ASSERT_EQUAL_STRING("321abc", str);
    iniparser_freedict(dic);
    dic = NULL;
    /*test extra large values*/
    dic = dictionary_new(0);
    TEST_ASSERT_NOT_NULL(dic);
    memset(val, '\\', sizeof(val)-1);
    ret = iniparser_set(dic, ":key1", val);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, ret, "cannot set :key1"
                                         " in: " TMP_INI_PATH);
    ini = fopen(TMP_INI_PATH, "wt");
    TEST_ASSERT_NOT_NULL_MESSAGE(ini, "cannot open " TMP_INI_PATH);
    iniparser_dump_ini(dic, ini);
    fclose(ini);
    ini = NULL;
    iniparser_freedict(dic);
    dic = NULL;
}

void test_iniparser_dumpsection_ini(void)
{
    const char *str;
    char key[4096] = {};
    int ret;

    /*loading old.ini*/
    dic = iniparser_load(OLD_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " OLD_INI_PATH);
    /*check the data of old.ini*/
    str = iniparser_getstring(dic,"section:key_01",NULL);
    TEST_ASSERT_EQUAL_STRING("hello world", str);
    str = iniparser_getstring(dic,"section:key1",NULL);
    TEST_ASSERT_EQUAL_STRING("321abc", str);
    /*open test.ini*/
    ini = fopen(TEST_INI_PATH,"w");
    TEST_ASSERT_NOT_NULL_MESSAGE(ini, "cannot open " TEST_INI_PATH);
    /*dump the data of old.ini to test.ini*/
    iniparser_dumpsection_ini(dic,"section",ini);
    fclose(ini);
    ini = NULL;
    iniparser_freedict(dic);
    dic = NULL;
    /*loading test.ini*/
    dic = iniparser_load(TEST_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " TEST_INI_PATH);
    /*check the data of test.ini*/
    str = iniparser_getstring(dic,"section:key_01",NULL);
    TEST_ASSERT_EQUAL_STRING("hello world", str);
    str = iniparser_getstring(dic,"section:key1",NULL);
    TEST_ASSERT_EQUAL_STRING("321abc", str);
    iniparser_freedict(dic);
    dic = NULL;
    /*test extra large keys*/
    dic = dictionary_new(0);
    TEST_ASSERT_NOT_NULL(dic);
    memset(key, 'a', sizeof(key)-1);
    ret = iniparser_set(dic, key, "dummy");
    TEST_ASSERT_GREATER_OR_EQUAL(0, ret);
    ini = fopen(TMP_INI_PATH, "wt");
    TEST_ASSERT_NOT_NULL_MESSAGE(ini, "cannot open " TMP_INI_PATH);
    /*dump the data of old.ini to test.ini*/
    iniparser_dumpsection_ini(dic,key,ini);
    fclose(ini);
    ini = NULL;
    iniparser_freedict(dic);
    dic = NULL;
}

void test_iniparser_find_entry(void)
{
    int i, ret;

    /* NULL test */
    ret = iniparser_find_entry(NULL, NULL);
    TEST_ASSERT_EQUAL(0, ret);
    ret = iniparser_find_entry(NULL, "dummy");
    TEST_ASSERT_EQUAL(0, ret);

    /* Empty dictionary test*/
    dic = dictionary_new(10);
    TEST_ASSERT_NOT_NULL(dic);
    ret = iniparser_find_entry(dic, NULL);
    TEST_ASSERT_EQUAL(0, ret);
    ret = iniparser_find_entry(dic, "dummy");
    TEST_ASSERT_EQUAL(0, ret);
    dictionary_del(dic);
    dic = NULL;

    /*Regular dictionary */
    dic = generate_dictionary(1, 8);
    TEST_ASSERT_NOT_NULL(dic);
    for (i = 1; i < 8; i++)
    {
        ret = iniparser_find_entry(dic, dic->key[i]);
        TEST_ASSERT_EQUAL(1, ret);
    }
    ret = iniparser_find_entry(dic, "dummy");
    TEST_ASSERT_EQUAL(0, ret);

    iniparser_freedict(dic);
    dic = NULL;
}

void test_iniparser_utf8(void)
{
    const char *str;
    int ret;

    dic = iniparser_load(GRUEZI_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " GRUEZI_INI_PATH);

    /* Generic dictionary */
    str = iniparser_getstring(dic, "Chuchichäschtli:10.123", NULL);
    TEST_ASSERT_EQUAL_STRING("example", str);
    str = iniparser_getstring(dic, "Chuchichäschtli:Gruss", NULL);
    TEST_ASSERT_EQUAL_STRING("Grüzi", str);
    dictionary_del(dic);
    dic = iniparser_load(UTF8_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " UTF8_INI_PATH);

    /* Generic dictionary */
    ret = iniparser_getboolean(dic, "拉麺:叉焼", -1);
    TEST_ASSERT_EQUAL(0, ret);
    ret = iniparser_getboolean(dic, "拉麺:味噌", -1);
    TEST_ASSERT_EQUAL(1, ret);
    ret = iniparser_getboolean(dic, "拉麺:海苔", -1);
    TEST_ASSERT_EQUAL(0, ret);
    str = iniparser_getstring(dic, "拉麺:メンマ", NULL);
    TEST_ASSERT_EQUAL_STRING("そうだね", str);
    dictionary_del(dic);
    dic = NULL;
}

static void create_empty_ini_file(const char *filename)
{
    ini = fopen(filename, "w");
    TEST_ASSERT_NOT_NULL_MESSAGE(ini, filename);
    fclose(ini);
    ini = NULL;
}

void test_iniparser_misformed(void)
{
    int ret;

    create_empty_ini_file(TMP_INI_PATH);
    dic = iniparser_load(TMP_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " TMP_INI_PATH);

    ret = iniparser_set(dic, MISFORMED_INI_SEC0, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, ret, "cannot set section "
                                         MISFORMED_INI_SEC0 " in: "
                                         TMP_INI_PATH);
    iniparser_set(dic, MISFORMED_INI_SEC0 ":" MISFORMED_INI_ATTR, "2222");
    /* test dictionary */
    ret = iniparser_getint(dic, MISFORMED_INI_SEC0 ":" MISFORMED_INI_ATTR, -1);
    TEST_ASSERT_EQUAL(2222, ret);
    ini = fopen(TMP_INI_PATH, "w+");
    TEST_ASSERT_NOT_NULL_MESSAGE(ini, "cannot open " TMP_INI_PATH);

    iniparser_dump_ini(dic, ini);
    fclose(ini);
    ini = NULL;
    dictionary_del(dic);
    /* check if section has been written as expected */
    dic = iniparser_load(TMP_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " TMP_INI_PATH);

    ret = iniparser_getint(dic, MISFORMED_INI_SEC0 ":" MISFORMED_INI_ATTR, -1);
    TEST_ASSERT_EQUAL(2222, ret);
    dictionary_del(dic);
    dic = NULL;
    ret = remove(TMP_INI_PATH);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, ret, "cannot remove " TMP_INI_PATH);

    create_empty_ini_file(TMP_INI_PATH);
    dic = iniparser_load(TMP_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " TMP_INI_PATH);

    ret = iniparser_set(dic, MISFORMED_INI_SEC1, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, ret, "cannot set section "
                                         MISFORMED_INI_SEC1 " in: "
                                         TMP_INI_PATH);

    iniparser_set(dic, MISFORMED_INI_SEC1 ":" MISFORMED_INI_ATTR, "2222");
    /* test dictionary */
    ret = iniparser_getint(dic, MISFORMED_INI_SEC1 ":" MISFORMED_INI_ATTR, -1);
    TEST_ASSERT_EQUAL(2222, ret);
    ini = fopen(TMP_INI_PATH, "w+");
    TEST_ASSERT_NOT_NULL_MESSAGE(ini, "cannot open " TMP_INI_PATH);

    iniparser_dump_ini(dic, ini);
    fclose(ini);
    ini = NULL;
    dictionary_del(dic);
    /* check if section has been written as expected */
    dic = iniparser_load(TMP_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " TMP_INI_PATH);

    ret = iniparser_getint(dic, MISFORMED_INI_SEC1 ":" MISFORMED_INI_ATTR, -1);
    TEST_ASSERT_EQUAL(2222, ret);
    dictionary_del(dic);
    dic = NULL;
    ret = remove(TMP_INI_PATH);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, ret, "cannot remove " TMP_INI_PATH);

    create_empty_ini_file(TMP_INI_PATH);
    dic = iniparser_load(TMP_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " TMP_INI_PATH);

    ret = iniparser_set(dic, MISFORMED_INI_SEC2, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, ret, "cannot set section "
                                         MISFORMED_INI_SEC2 " in: "
                                         TMP_INI_PATH);

    iniparser_set(dic, MISFORMED_INI_SEC2 ":" MISFORMED_INI_ATTR, "2222");
    /* test dictionary */
    ret = iniparser_getint(dic, MISFORMED_INI_SEC2 ":" MISFORMED_INI_ATTR, -1);
    TEST_ASSERT_EQUAL(2222, ret);
    ini = fopen(TMP_INI_PATH, "w+");
    TEST_ASSERT_NOT_NULL_MESSAGE(ini, "cannot open " TMP_INI_PATH);

    iniparser_dump_ini(dic, ini);
    fclose(ini);
    ini = NULL;
    dictionary_del(dic);
    /* check if section has been written as expected */
    dic = iniparser_load(TMP_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " TMP_INI_PATH);

    ret = iniparser_getint(dic, MISFORMED_INI_SEC2 ":" MISFORMED_INI_ATTR, -1);
    TEST_ASSERT_EQUAL(2222, ret);
    dictionary_del(dic);
    dic = NULL;
    ret = remove(TMP_INI_PATH);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, ret, "cannot remove " TMP_INI_PATH);
}

void test_iniparser_quotes(void)
{
    const char *str;
    int ret;

    /**
     * Test iniparser_load()
     */
    /* check if section has been written as expected */
    dic = iniparser_load(QUOTES_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load "  QUOTES_INI_PATH);

    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR0, NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL0, str);
    /*
     * iniparser_load() supports semicolon and hash in values if they are
     * quoted
     */
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR1, NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL1, str);
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR2, NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL2, str);
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR3, NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL0, str);
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR4, NULL);
    TEST_ASSERT_EQUAL_STRING("str", str);
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR5, NULL);
    TEST_ASSERT_EQUAL_STRING("str", str);
    /*
     * iniparser_load() supports quotes in attributes
     */
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" "str\"ing", NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL0, str);
    /*
     * iniparser_load() does not support semicolon or hash in attributes
     */
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" "str;ing", NULL);
    TEST_ASSERT_NULL(str);
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" "str#ing", NULL);
    TEST_ASSERT_NULL(str);
    /*
     * iniparser_load() does support colon in attributes
     */
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" "str:ing", NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL0, str);
    ini = fopen(TMP_INI_PATH, "w+");
    TEST_ASSERT_NOT_NULL_MESSAGE(ini, "cannot open " TMP_INI_PATH);

    /**
     * Test iniparser_dump_ini()
     */
    iniparser_dump_ini(dic, ini);
    fclose(ini);
    ini = NULL;
    dictionary_del(dic);
    dic = iniparser_load(TMP_INI_PATH);

    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR0, NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL0, str);
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR1, NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL1, str);
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR2, NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL2, str);
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR3, NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL0, str);
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR4, NULL);
    TEST_ASSERT_EQUAL_STRING("str", str);
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR5, NULL);
    TEST_ASSERT_EQUAL_STRING("str", str);
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" "str\"ing", NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL0, str);
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" "str;ing", NULL);
    TEST_ASSERT_NULL(str);
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" "str#ing", NULL);
    TEST_ASSERT_NULL(str);
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" "str:ing", NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL0, str);
    dictionary_del(dic);
    dic = NULL;
    ret = remove(TMP_INI_PATH);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, ret, "cannot remove " TMP_INI_PATH);
    /**
     * test iniparser_set()
     */
    create_empty_ini_file(TMP_INI_PATH);
    dic = iniparser_load(TMP_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " TMP_INI_PATH);

    ret = iniparser_set(dic, QUOTES_INI_SEC, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, ret, "cannot set " QUOTES_INI_SEC
                                         " in: " TMP_INI_PATH);

    /* test dictionary */
    iniparser_set(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR0, QUOTES_INI_VAL0);
    /* iniparser_set() supports quotes in values */
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR0, NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL0, str);
    ini = fopen(TMP_INI_PATH, "w+");
    TEST_ASSERT_NOT_NULL_MESSAGE(ini, "cannot open " TMP_INI_PATH);

    iniparser_dump_ini(dic, ini);
    fclose(ini);
    ini = NULL;
    dictionary_del(dic);
    /* check if section has been written as expected */
    dic = iniparser_load(TMP_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " TMP_INI_PATH);

    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR0, NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL0, str);
    dictionary_del(dic);
    dic = NULL;
    ret = remove(TMP_INI_PATH);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, ret, "cannot remove " TMP_INI_PATH);

    /*
     * test semicolon comment
     */
    create_empty_ini_file(TMP_INI_PATH);
    dic = iniparser_load(TMP_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " TMP_INI_PATH);

    ret = iniparser_set(dic, QUOTES_INI_SEC, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, ret, "cannot set " QUOTES_INI_SEC
                                         " in: " TMP_INI_PATH);

    /* test dictionary */
    iniparser_set(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR1, QUOTES_INI_VAL1);
    /* iniparser_set() supports ; in values */
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR1, NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL1, str);
    ini = fopen(TMP_INI_PATH, "w+");
    TEST_ASSERT_NOT_NULL_MESSAGE(ini, "cannot open " TMP_INI_PATH);

    iniparser_dump_ini(dic, ini);
    fclose(ini);
    ini = NULL;
    dictionary_del(dic);
    /* check if section has been written as expected */
    dic = iniparser_load(TMP_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " TMP_INI_PATH);

    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR1, NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL1, str);
    dictionary_del(dic);
    dic = NULL;
    ret = remove(TMP_INI_PATH);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, ret, "cannot remove " TMP_INI_PATH);

    /*
     * test hash comment
     */
    create_empty_ini_file(TMP_INI_PATH);
    dic = iniparser_load(TMP_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " TMP_INI_PATH);

    ret = iniparser_set(dic, QUOTES_INI_SEC, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, ret, "cannot set " QUOTES_INI_SEC
                                         " in: " TMP_INI_PATH);

    /* test dictionary */
    iniparser_set(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR2, QUOTES_INI_VAL2);
    /* iniparser_set() supports # in values */
    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR2, NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL2, str);
    ini = fopen(TMP_INI_PATH, "w+");
    TEST_ASSERT_NOT_NULL_MESSAGE(ini, "cannot open " TMP_INI_PATH);

    iniparser_dump_ini(dic, ini);
    fclose(ini);
    ini = NULL;
    dictionary_del(dic);
    /* check if section has been written as expected */
    dic = iniparser_load(TMP_INI_PATH);
    TEST_ASSERT_NOT_NULL_MESSAGE(dic, "cannot load " TMP_INI_PATH);

    str = iniparser_getstring(dic, QUOTES_INI_SEC ":" QUOTES_INI_ATTR2, NULL);
    TEST_ASSERT_EQUAL_STRING(QUOTES_INI_VAL2, str);
    dictionary_del(dic);
    dic = NULL;
    ret = remove(TMP_INI_PATH);
    TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(0, ret, "cannot remove " TMP_INI_PATH);
}
