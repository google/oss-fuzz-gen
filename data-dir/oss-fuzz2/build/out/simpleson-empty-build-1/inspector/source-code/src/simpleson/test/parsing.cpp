#include "json.h"
#include "test.h"

typedef struct test_struct_struct
{
    const char *input;
    const char *output;
    json::jtype::jtype type;
} test_struct_t;

const test_struct_t test_data[] = { 
    { "\"Hello World\"", "\"Hello World\"", json::jtype::jstring },
    { "\"Hello World\\\"\"", "\"Hello World\\\"\"", json::jtype::jstring },
    { "true", "true", json::jtype::jbool },
    { "false", "false", json::jtype::jbool },
    { "null", "null", json::jtype::jnull },
    { "[]", "[]", json::jtype::jarray },
    { "[\"Hello World\"]", "[\"Hello World\"]", json::jtype::jarray },
    { "[\"Hello World\",true,false,null]", "[\"Hello World\",true,false,null]", json::jtype::jarray },
    { "{}", "{}", json::jtype::jobject},
    { "{\"hello\":\"world\"}", "{\"hello\":\"world\"}", json::jtype::jobject},
    { "[{\"hello\":\"world\"},{\"hello\":\"world\"}]", "[{\"hello\":\"world\"},{\"hello\":\"world\"}]", json::jtype::jarray}
};

const char *test_numbers[] = { "0", "-0", "123", "-123", "0.123", "-0.123", "123.456", "-123.456", "123e456", "123e+456", "123e-456", "123.456e789", "123.456e+789", "123.456e-789" };

int main(void)
{
    json::reader stream;

    const size_t data_points = sizeof(test_data) / sizeof(test_struct_t);
    size_t i,j;

    for(i = 0; i < data_points; i++) {
        const test_struct_t data_point = test_data[i];
        for(j = 0; j < strlen(data_point.input); j++) {
            TEST_EQUAL(stream.push(data_point.input[j]), json::reader::ACCEPTED);
        }
        TEST_EQUAL(stream.type(), data_point.type);
        TEST_STRING_EQUAL(stream.readout().c_str(), data_point.output);
        stream.clear();
    }

    // Verify iteration through the data
    TEST_TRUE(i > 0);

    const size_t num_num = sizeof(test_numbers) / sizeof(char*);
    for(i = 0; i < num_num; i++) {
        const char *data_point = test_numbers[i];
        for(j = 0; j < strlen(data_point); j++) {
            TEST_EQUAL(stream.push(data_point[j]), json::reader::ACCEPTED);
        }
        TEST_EQUAL(stream.push(' '), json::reader::REJECTED);
        TEST_EQUAL(stream.type(), json::jtype::jnumber);
        TEST_STRING_EQUAL(stream.readout().c_str(), data_point);
        stream.clear();
    }
}