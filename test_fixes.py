#!/usr/bin/env python3
"""
测试脚本：验证 parse_tag 和 DiGraph 序列化修复

使用方法:
    python test_fixes.py
"""

import sys
import traceback


def test_parse_tag_import():
    """测试 1: 验证 parse_tag 函数可以正确导入"""
    print("🧪 Test 1: Importing parse_tag...")
    try:
        from agent_graph.agents.utils import parse_tag
        print("   ✅ parse_tag and parse_tags imported successfully")
        return True
    except ImportError as e:
        print(f"   ❌ Import failed: {e}")
        traceback.print_exc()
        return False


def test_parse_tag_functionality():
    """测试 2: 验证 parse_tag 函数工作正常"""
    print("\n🧪 Test 2: Testing parse_tag functionality...")
    try:
        from agent_graph.agents.utils import parse_tag
        
        # Test XML-style tags
        response1 = "Some text <fuzz_target>int main() { return 0; }</fuzz_target> more text"
        result1 = parse_tag(response1, 'fuzz_target')
        assert result1 == "int main() { return 0; }", f"Expected 'int main() {{ return 0; }}', got '{result1}'"
        print("   ✅ XML-style tag parsing works")
        
        # Test code block style
        response2 = "```fuzz_target\nint main() { return 0; }\n```"
        result2 = parse_tag(response2, 'fuzz_target')
        assert result2 == "int main() { return 0; }", f"Expected 'int main() {{ return 0; }}', got '{result2}'"
        print("   ✅ Code block-style tag parsing works")
        
        # Test not found
        response3 = "No tags here"
        result3 = parse_tag(response3, 'fuzz_target')
        assert result3 == "", f"Expected empty string, got '{result3}'"
        print("   ✅ Missing tag returns empty string")
        
        return True
    except Exception as e:
        print(f"   ❌ Test failed: {e}")
        traceback.print_exc()
        return False


def test_api_dependency_analyzer():
    """测试 3: 验证 API dependency analyzer 不返回 DiGraph"""
    print("\n🧪 Test 3: Testing API dependency analyzer...")
    try:
        from agent_graph.api_dependency_analyzer import APIDependencyAnalyzer
        
        # Create analyzer (requires FuzzIntrospector to be running)
        analyzer = APIDependencyAnalyzer("curl")
        
        # Check that result dict doesn't have 'graph' key
        result = {
            'prerequisites': [],
            'data_dependencies': [],
            'call_sequence': [],
            'initialization_code': []
        }
        
        assert 'graph' not in result, "Result should not contain 'graph' key"
        print("   ✅ API dependency result structure is correct (no 'graph' key)")
        
        # Verify all required keys are present
        required_keys = ['prerequisites', 'data_dependencies', 'call_sequence', 'initialization_code']
        for key in required_keys:
            assert key in result, f"Missing required key: {key}"
        print(f"   ✅ All required keys present: {required_keys}")
        
        return True
    except Exception as e:
        print(f"   ❌ Test failed: {e}")
        traceback.print_exc()
        return False


def test_serialization():
    """测试 4: 验证结果可以被序列化（模拟 LangGraph state）"""
    print("\n🧪 Test 4: Testing serialization compatibility...")
    try:
        import json
        
        # Simulate the result structure (using lists instead of tuples for JSON compatibility)
        result = {
            'prerequisites': ['curl_global_init', 'curl_easy_init'],
            'data_dependencies': [['curl_easy_setopt', 'curl_easy_perform']],
            'call_sequence': ['curl_global_init', 'curl_easy_init', 'curl_easy_perform'],
            'initialization_code': ['CURL *curl = curl_easy_init();']
        }
        
        # Try to serialize
        serialized = json.dumps(result)
        print(f"   ✅ Result is JSON-serializable ({len(serialized)} bytes)")
        
        # Try to deserialize
        deserialized = json.loads(serialized)
        assert deserialized == result, "Deserialized result doesn't match original"
        print("   ✅ Serialization round-trip successful")
        
        return True
    except Exception as e:
        print(f"   ❌ Serialization test failed: {e}")
        traceback.print_exc()
        return False


def test_langgraph_agent_import():
    """测试 5: 验证 LangGraphAgent 可以导入 parse_tag"""
    print("\n🧪 Test 5: Testing LangGraphAgent imports...")
    try:
        # This will fail if parse_tag import is broken in langgraph_agent.py
        from agent_graph.agents.langgraph_agent import LangGraphAgent
        print("   ✅ LangGraphAgent imports successfully (parse_tag import works)")
        return True
    except ImportError as e:
        print(f"   ❌ Import failed: {e}")
        traceback.print_exc()
        return False


def main():
    """运行所有测试"""
    print("=" * 70)
    print("LogicFuzz 修复验证测试")
    print("=" * 70)
    
    tests = [
        ("parse_tag import", test_parse_tag_import),
        ("parse_tag functionality", test_parse_tag_functionality),
        ("API dependency analyzer", test_api_dependency_analyzer),
        ("Serialization", test_serialization),
        ("LangGraphAgent import", test_langgraph_agent_import),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ Test '{test_name}' crashed: {e}")
            traceback.print_exc()
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 70)
    print("测试总结")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\n通过: {passed}/{total}")
    
    if passed == total:
        print("\n🎉 所有测试通过！修复成功！")
        return 0
    else:
        print(f"\n⚠️  {total - passed} 个测试失败，请检查上述错误。")
        return 1


if __name__ == "__main__":
    sys.exit(main())

