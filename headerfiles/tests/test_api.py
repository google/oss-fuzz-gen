import headerfiles.api as api

def test_is_supported_proj():
    assert api.is_supported_proj("libfdk-aac")
    assert api.is_supported_proj("libfuse")
    assert api.is_supported_proj("libpsl")
    assert api.is_supported_proj("libsodium")
    assert api.is_supported_proj("libtasn1")
    assert not api.is_supported_proj("aaa")

def check_result_is_list_of_strings(result: list):
    assert isinstance(result, list)
    assert len(result) == 0 or all(isinstance(x, str) for x in result)

def test_get_proj_headers():
    check_result_is_list_of_strings(api.get_proj_headers("libfdk-aac"))
    check_result_is_list_of_strings(api.get_proj_headers("libfuse"))
    check_result_is_list_of_strings(api.get_proj_headers("libpsl"))
    check_result_is_list_of_strings(api.get_proj_headers("libsodium"))
    check_result_is_list_of_strings(api.get_proj_headers("libtasn1"))
    assert api.get_proj_headers("aaa") is None

if __name__ == "__main__":
    import pytest
    pytest.main()
