#include <unity.h>

/* We need to directly insert the .c file in order to test the */
/* static functions as well */
#include "dictionary.c"

void setUp(void)
{
}

void tearDown(void)
{
}

void test_xstrdup(void)
{
    size_t i;
    char *dup_str;
    const char *strings[] = {
        "",
        "test",
        " "
    };
    char *string_very_long;

    /* NULL test */
    TEST_ASSERT_NULL(xstrdup(NULL));

    for (i = 0 ; i < sizeof(strings) / sizeof(char *) ; ++i) {
        dup_str = xstrdup(strings[i]);
        TEST_ASSERT_EQUAL_STRING(strings[i], dup_str);
        free(dup_str);
    }

    /* test a overflowing string */
    string_very_long = (char*) malloc(10 * 1024);
    memset(string_very_long, '#', 10 * 1024);
    string_very_long[10 * 1024 - 1] = '\0';
    dup_str = xstrdup(string_very_long);
    TEST_ASSERT_EQUAL_STRING(string_very_long, dup_str);

    free(string_very_long);
    free(dup_str);
}

void test_dictionary_grow(void)
{
    unsigned i;
    dictionary *dic;

    dic = dictionary_new(DICTMINSZ);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_EQUAL(0, dic->n);
    TEST_ASSERT_EQUAL(DICTMINSZ, dic->size);

    for (i = 1 ; i < 10 ; ++i) {
        TEST_ASSERT_EQUAL(0, dictionary_grow(dic));
        TEST_ASSERT_EQUAL(0, dic->n);
        TEST_ASSERT_EQUAL((1 << i) * DICTMINSZ, dic->size);
    }
    dictionary_del(dic);
}

void test_dictionary_hash(void)
{
    /* NULL test */
    TEST_ASSERT_EQUAL(0, dictionary_hash(NULL));
}

void test_dictionary_growing(void)
{
    int i, j;
    char sec_name[32];
    char key_name[64];
    dictionary *dic;

    dic = dictionary_new(DICTMINSZ);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_EQUAL(0, dic->n);

    /* Makes the dictionary grow */
    for (i = 1 ; i < 101; ++i) {
        sprintf(sec_name, "sec%d", i);
        TEST_ASSERT_EQUAL(0, dictionary_set(dic, sec_name, ""));
        for (j = 1 ; j < 11; ++j) {
            sprintf(key_name, "%s:key%d", sec_name, j);
            TEST_ASSERT_EQUAL(0, dictionary_set(dic, key_name, "dummy_value"));
            TEST_ASSERT_EQUAL(i + (i - 1) * 10 + j, dic->n);
        }
    }

    /* Shrink the dictionary */
    for (i = 100 ; i > 0; --i) {
        sprintf(sec_name, "sec%d", i);
        for (j = 10 ; j > 0; --j) {
            sprintf(key_name, "%s:key%d", sec_name, j);
            dictionary_unset(dic, key_name);
        }
        dictionary_unset(dic, sec_name);
        TEST_ASSERT_EQUAL((i - 1) * (11), dic->n);
    }

    dictionary_del(dic);
}

static char *get_dump(dictionary *d)
{
    FILE *fd;
    char *dump_buff;
    int dump_size;

    /* Dump the dictionary in temporary file */
    fd = tmpfile();
    if (fd == NULL)
        return NULL;
    dictionary_dump(d, fd);

    /* Retrieve the dump file */
    dump_size = ftell(fd);
    if (dump_size == -1) {
        fclose(fd);
        return NULL;
    }
    rewind(fd);

    dump_buff = (char*) calloc(1, dump_size + 1);
    if (dump_buff == NULL) {
        fclose(fd);
        return NULL;
    }
    if (fread(dump_buff, 1, dump_size, fd) != (size_t)dump_size) {
        fclose(fd);
        return NULL;
    }

    fclose(fd);
    return dump_buff;
}

void test_dictionary_unset(void)
{
    int i, j;
    char sec_name[32];
    char key_name[64];
    dictionary *dic1;
    dictionary *dic2;
    char *dic1_dump;
    char *dic2_dump;

    /* try dummy unsets */
    dictionary_unset(NULL, NULL);
    dictionary_unset(NULL, key_name);

    /* Generate two similar dictionaries */
    dic1 = dictionary_new(DICTMINSZ);
    TEST_ASSERT_NOT_NULL(dic1);
    for (i = 1 ; i < 10; ++i) {
        sprintf(sec_name, "sec%d", i);
        dictionary_set(dic1, sec_name, "");
        for (j = 1 ; j < 10; ++j) {
            sprintf(key_name, "%s:key%d", sec_name, j);
            dictionary_set(dic1, key_name, "dummy_value");
        }
    }
    dic2 = dictionary_new(DICTMINSZ);
    TEST_ASSERT_NOT_NULL(dic2);
    for (i = 1 ; i < 10; ++i) {
        sprintf(sec_name, "sec%d", i);
        dictionary_set(dic2, sec_name, "");
        for (j = 1 ; j < 10; ++j) {
            sprintf(key_name, "%s:key%d", sec_name, j);
            dictionary_set(dic2, key_name, "dummy_value");
        }
    }

    /* Make sure the dictionaries are the same */
    dic1_dump = get_dump(dic1);
    dic2_dump = get_dump(dic2);
    TEST_ASSERT_EQUAL_STRING(dic1_dump, dic2_dump);
    free(dic1_dump);
    free(dic2_dump);

    /* Those tests should not change the dictionary */
    dictionary_unset(dic2, NULL);
    dictionary_unset(dic2, "bad_key");

    /* dic1 and dic2 must still be the same */
    dic1_dump = get_dump(dic1);
    dic2_dump = get_dump(dic2);
    TEST_ASSERT_EQUAL_STRING(dic1_dump, dic2_dump);
    free(dic1_dump);
    free(dic2_dump);

    dictionary_del(dic1);
    dictionary_del(dic2);
}

void test_dictionary_dump(void)
{
    int i, j;
    char sec_name[32];
    char key_name[64];
    dictionary *dic;
    char *dump_buff;
    const char dump_real[] = "\
                sec1\t[]\n\
           sec1:key1\t[dummy_value]\n\
           sec1:key2\t[dummy_value]\n\
           sec1:key3\t[dummy_value]\n\
           sec1:key4\t[dummy_value]\n\
                sec2\t[]\n\
           sec2:key1\t[dummy_value]\n\
           sec2:key2\t[dummy_value]\n\
           sec2:key3\t[dummy_value]\n\
           sec2:key4\t[dummy_value]\n\
";

    dic = dictionary_new(DICTMINSZ);
    TEST_ASSERT_NOT_NULL(dic);

    /* Try dummy values */
    dictionary_dump(NULL, NULL);
    dictionary_dump(dic, NULL);

    /* Try with empty dictionary first */
    dump_buff = get_dump(dic);
    TEST_ASSERT_EQUAL_STRING("empty dictionary\n", dump_buff);
    free(dump_buff);

    /* Populate the dictionary */
    for (i = 1 ; i < 3; ++i) {
        sprintf(sec_name, "sec%d", i);
        dictionary_set(dic, sec_name, "");
        for (j = 1 ; j < 5; ++j) {
            sprintf(key_name, "%s:key%d", sec_name, j);
            dictionary_set(dic, key_name, "dummy_value");
        }
    }

    /* Check the dump file */
    dump_buff = get_dump(dic);
    TEST_ASSERT_EQUAL_STRING(dump_real, dump_buff);
    free(dump_buff);

    dictionary_del(dic);
}

void test_dictionary_get(void)
{
    dictionary *dic;
    int i, j;
    char sec_name[32];
    char key_name[64];

    /*NULL test*/
    TEST_ASSERT_NULL(dictionary_get(NULL, NULL, NULL));
    TEST_ASSERT_NULL(dictionary_get(NULL, "string", NULL));

    /*Check the def return element*/
    dic = dictionary_new(DICTMINSZ);
    TEST_ASSERT_NOT_NULL(dic);
    TEST_ASSERT_NULL(dictionary_get(dic, "dummy", NULL));
    TEST_ASSERT_EQUAL_STRING("def", dictionary_get(dic, NULL, "def"));
    TEST_ASSERT_EQUAL_STRING("def", dictionary_get(dic, "dummy", "def"));

    /*Populate the dictionary*/
    for (i = 1; i < 3; ++i)
    {
        sprintf(sec_name, "sec%d", i);
        dictionary_set(dic, sec_name, "");
        for (j = 1; j < 5; ++j)
        {
            sprintf(key_name, "%s:key%d", sec_name, j);
            dictionary_set(dic, key_name, "dummy_value");
            TEST_ASSERT_EQUAL_STRING("dummy_value",
                                     dictionary_get(dic, key_name, "string"));
        }
    }

    /*Test get dictionary section value*/
    TEST_ASSERT_EQUAL_STRING("",
                             dictionary_get(dic, "sec1", NULL));
    TEST_ASSERT_EQUAL_STRING("",
                             dictionary_get(dic, "sec1", "def"));

    /*delete and set a key in a dictionary*/
    dictionary_unset(dic, "sec1:key4");
    TEST_ASSERT_EQUAL_STRING("def",
                             dictionary_get(dic, "sec1:key4", "def"));
    dictionary_set(dic, "sec1:key4", "dummy_value");
    TEST_ASSERT_EQUAL_STRING("dummy_value",
                             dictionary_get(dic, "sec1:key4", "def"));

    dictionary_del(dic);
}
