#include "json.h"
#include "../test/test.h"
#include <iostream>

int main(void)
{
    const char *test = "{\"key\":\"value\\\"\"}";
    json::jobject result = json::jobject::parse(test);
    const std::string echo = result.as_string();
    TEST_STRING_EQUAL(test, echo.c_str());
    test = "{ \"0\": {\"key\":\"value\\\"\"} }";
    std::cout << test;
    std::cout << "\n";
    result = json::jobject::parse(test);
    std::cout << result.as_string() + "\n";
    json::jobject inner_obj = result["0"];
    std::cout << inner_obj.as_string();
    TEST_STRING_EQUAL(inner_obj.as_string().c_str(), "{\"key\":\"value\\\"\"}");
    std::string inner = result["0"].as_string();
    TEST_STRING_EQUAL(inner.c_str(), "{\"key\":\"value\\\"\"}");
}