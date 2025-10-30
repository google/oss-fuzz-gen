#!/usr/bin/env python3
"""
Unified API analyzer for conti-benchmark YAML files.
Identifies valueless APIs and optionally removes them.
"""

import os
import json
import yaml
import re
import argparse
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple

# Define patterns for identifying valueless APIs
VALUELESS_PATTERNS = {
    'anonymous_namespace': {
        'pattern': r'_GLOBAL__N_',
        'description': 'C++ anonymous namespace internal function'
    },
    'lambda_expression': {
        'pattern': r'\$_\d+',
        'description': 'C++ lambda expression'
    },
    'memory_management': {
        'keywords': ['alloc', 'free', 'finalize', 'destroy', 'cleanup', 'delete', 'release', 'dispose'],
        'description': 'Internal memory management function'
    },
    'internal_helper': {
        'keywords': ['append', '_init', 'reset', 'clear', '_copy', '_clone'],
        'description': 'Internal helper/utility function'
    },
    'mock_test': {
        'keywords': ['mock', 'stub', 'test_', 'fake', 'dummy'],
        'description': 'Mock/Test/Stub function'
    },
    'destructor': {
        'pattern': r'~\w+|_ZN.*D[012]E',
        'description': 'Destructor function'
    },
    'private_internal': {
        'keywords': ['_internal', '_private', '__'],
        'description': 'Private/internal method'
    }
}


def is_valueless_api(func_info: Dict) -> Tuple[bool, List[str]]:
    """
    Determine if an API is valueless for fuzzing.
    
    Returns: (is_valueless, reasons)
    """
    reasons = []
    func_name = func_info.get('name', '')
    signature = func_info.get('signature', '')
    
    # Check anonymous namespace
    if re.search(VALUELESS_PATTERNS['anonymous_namespace']['pattern'], func_name):
        reasons.append(VALUELESS_PATTERNS['anonymous_namespace']['description'])
    
    # Check lambda expression
    if re.search(VALUELESS_PATTERNS['lambda_expression']['pattern'], func_name):
        reasons.append(VALUELESS_PATTERNS['lambda_expression']['description'])
    
    # Check destructor
    if re.search(VALUELESS_PATTERNS['destructor']['pattern'], func_name):
        reasons.append(VALUELESS_PATTERNS['destructor']['description'])
    
    # Check memory management functions
    func_name_lower = func_name.lower()
    for keyword in VALUELESS_PATTERNS['memory_management']['keywords']:
        if keyword in func_name_lower:
            reasons.append(f"{VALUELESS_PATTERNS['memory_management']['description']} (keyword: {keyword})")
            break
    
    # Check internal helper functions
    for keyword in VALUELESS_PATTERNS['internal_helper']['keywords']:
        if keyword in func_name_lower:
            reasons.append(f"{VALUELESS_PATTERNS['internal_helper']['description']} (keyword: {keyword})")
            break
    
    # Check mock/test functions
    for keyword in VALUELESS_PATTERNS['mock_test']['keywords']:
        if keyword in func_name_lower:
            reasons.append(f"{VALUELESS_PATTERNS['mock_test']['description']} (keyword: {keyword})")
            break
    
    # Check private/internal methods
    for keyword in VALUELESS_PATTERNS['private_internal']['keywords']:
        if keyword in func_name_lower:
            reasons.append(f"{VALUELESS_PATTERNS['private_internal']['description']} (keyword: {keyword})")
            break
    
    # Check C++ methods with only 'this' parameter
    params = func_info.get('params', [])
    if len(params) == 1 and params[0].get('name') == 'this':
        reasons.append('C++ parameterless member method (likely internal state access)')
    
    # Check functions with no parameters
    if len(params) == 0:
        reasons.append('Function with no parameters (likely internal state management)')
    
    return len(reasons) > 0, reasons


def parse_custom_yaml(content: str) -> Dict:
    """
    Custom YAML parser for handling non-standard formats.
    """
    lines = content.split('\n')
    data = {
        'functions': [],
        'language': '',
        'project': '',
        'target_name': '',
        'target_path': ''
    }
    
    current_func = None
    current_param = None
    
    for line in lines:
        line = line.rstrip()
        if not line or line.startswith('#'):
            continue
        
        # Parse function
        if line.startswith('- "name":'):
            if current_func:
                data['functions'].append(current_func)
            current_func = {'name': '', 'params': [], 'return_type': '', 'signature': ''}
            name = line.split('"name":', 1)[1].strip().strip('"')
            current_func['name'] = name
        elif line.startswith('  "params":'):
            continue
        elif line.startswith('  - "name":') and current_func:
            if current_param:
                current_func['params'].append(current_param)
            current_param = {'name': '', 'type': ''}
            name = line.split('"name":', 1)[1].strip().strip('"')
            current_param['name'] = name
        elif line.startswith('    "type":') and current_param:
            type_val = line.split('"type":', 1)[1].strip().strip('"')
            current_param['type'] = type_val
        elif line.startswith('  "return_type":') and current_func:
            if current_param:
                current_func['params'].append(current_param)
                current_param = None
            ret_type = line.split('"return_type":', 1)[1].strip().strip('"')
            current_func['return_type'] = ret_type
        elif line.startswith('  "signature":') and current_func:
            sig = line.split('"signature":', 1)[1].strip().strip('"')
            current_func['signature'] = sig
        elif line.startswith('"language":'):
            data['language'] = line.split('"language":', 1)[1].strip().strip('"')
        elif line.startswith('"project":'):
            data['project'] = line.split('"project":', 1)[1].strip().strip('"')
        elif line.startswith('"target_name":'):
            data['target_name'] = line.split('"target_name":', 1)[1].strip().strip('"')
        elif line.startswith('"target_path":'):
            data['target_path'] = line.split('"target_path":', 1)[1].strip().strip('"')
    
    if current_func:
        data['functions'].append(current_func)
    
    return data


def analyze_yaml_file(file_path: Path, base_dir: Path) -> Dict:
    """
    Analyze a single YAML file.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
        # Try standard YAML parsing first
        try:
            data = yaml.safe_load(content)
        except:
            # Fall back to custom parsing
            data = parse_custom_yaml(content)
    
    if not data or 'functions' not in data:
        return {
            'file': str(file_path.relative_to(base_dir)),
            'project': data.get('project', 'unknown') if data else 'unknown',
            'total_apis': 0,
            'valueless_apis': [],
            'valuable_apis': []
        }
    
    functions = data.get('functions', [])
    if not isinstance(functions, list):
        functions = [functions]
    
    valueless_apis = []
    valuable_apis = []
    
    for func in functions:
        if not isinstance(func, dict):
            continue
        
        is_invalid, reasons = is_valueless_api(func)
        
        api_info = {
            'name': func.get('name', ''),
            'signature': func.get('signature', ''),
        }
        
        if is_invalid:
            api_info['reasons'] = reasons
            valueless_apis.append(api_info)
        else:
            valuable_apis.append(api_info)
    
    return {
        'file': str(file_path.relative_to(base_dir)),
        'project': data.get('project', 'unknown'),
        'total_apis': len(functions),
        'valueless_count': len(valueless_apis),
        'valuable_count': len(valuable_apis),
        'valueless_apis': valueless_apis,
        'valuable_apis': valuable_apis
    }


def analyze_all_yamls(base_dir: Path) -> Tuple[List[Dict], Dict]:
    """
    Analyze all YAML files in the benchmark directory.
    
    Returns: (results, statistics)
    """
    # Collect all YAML files
    yaml_files = []
    for subdir in ['comparison', 'conti-cmp']:
        subdir_path = base_dir / subdir
        if subdir_path.exists():
            yaml_files.extend(subdir_path.glob('*.yaml'))
    
    # Include root directory YAML files
    yaml_files.extend([f for f in base_dir.glob('*.yaml') if f.is_file()])
    
    print(f"Found {len(yaml_files)} YAML files\n")
    
    # Analyze all files
    results = []
    for yaml_file in sorted(yaml_files):
        print(f"Analyzing: {yaml_file.name}...")
        result = analyze_yaml_file(yaml_file, base_dir)
        results.append(result)
    
    # Calculate statistics
    total_apis = sum(r['total_apis'] for r in results)
    total_valueless = sum(r['valueless_count'] for r in results)
    total_valuable = sum(r['valuable_count'] for r in results)
    
    statistics = {
        'total_projects': len(results),
        'total_apis': total_apis,
        'valueless_apis': total_valueless,
        'valuable_apis': total_valuable,
        'valueless_percentage': round(total_valueless / total_apis * 100, 2) if total_apis > 0 else 0
    }
    
    return results, statistics


def generate_json_report(results: List[Dict], statistics: Dict, output_path: Path):
    """
    Generate JSON report.
    """
    # Group valueless APIs by project
    valueless_by_project = {}
    for result in results:
        if result['valueless_count'] > 0:
            project = result['project']
            if project not in valueless_by_project:
                valueless_by_project[project] = []
            
            for api in result['valueless_apis']:
                valueless_by_project[project].append({
                    'file': result['file'],
                    'api': api['name'],
                    'signature': api['signature'],
                    'reasons': api['reasons']
                })
    
    # Create report structure
    report = {
        'summary': statistics,
        'valueless_api_rules': {
            key: pattern.get('description', '') 
            for key, pattern in VALUELESS_PATTERNS.items()
        },
        'valueless_apis_by_project': valueless_by_project,
        'all_files': results
    }
    
    # Save JSON report
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"✓ JSON report saved to: {output_path}")


def remove_valueless_apis(results: List[Dict], base_dir: Path, dry_run: bool = False):
    """
    Remove valueless APIs from YAML files.
    """
    # Group APIs by file
    apis_by_file = {}
    for result in results:
        if result['valueless_count'] > 0:
            file_path = result['file']
            if file_path not in apis_by_file:
                apis_by_file[file_path] = []
            apis_by_file[file_path].extend([api['name'] for api in result['valueless_apis']])
    
    if not apis_by_file:
        print("No valueless APIs to remove.")
        return
    
    print(f"\n{'DRY RUN: ' if dry_run else ''}Found {sum(len(apis) for apis in apis_by_file.values())} valueless APIs in {len(apis_by_file)} files")
    
    if not dry_run:
        response = input("\n⚠️  This will modify YAML files. Continue? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Operation cancelled.")
            return
    
    # Process each file
    modified_count = 0
    for relative_path, api_names in apis_by_file.items():
        file_path = base_dir / relative_path
        
        if not file_path.exists():
            print(f"❌ File not found: {relative_path}")
            continue
        
        print(f"\n{'[DRY RUN] ' if dry_run else ''}Processing: {relative_path}")
        print(f"  APIs to remove: {len(api_names)}")
        for api in api_names:
            print(f"    - {api}")
        
        if dry_run:
            continue
        
        # Backup original file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = file_path.with_suffix(f'.yaml.backup_{timestamp}')
        shutil.copy2(file_path, backup_path)
        print(f"  ✓ Backed up to: {backup_path.name}")
        
        # Read and modify content
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        new_lines = []
        skip_until_next = False
        
        for i, line in enumerate(lines):
            # Check if this is a function definition
            if line.startswith('- "name":'):
                func_name = line.split('"name":', 1)[1].strip().strip('"')
                
                if func_name in api_names:
                    # Start skipping this function
                    skip_until_next = True
                    continue
                else:
                    # Not a target function, stop skipping
                    skip_until_next = False
            
            # Skip lines if we're removing a function
            if skip_until_next:
                # Stop skipping at next function or metadata
                if line.startswith('- "name":') or line.startswith('"language":') or line.startswith('"project":'):
                    skip_until_next = False
                    new_lines.append(line)
            else:
                new_lines.append(line)
        
        # Write modified content
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        
        modified_count += 1
        print(f"  ✓ Modified")
    
    if not dry_run:
        print(f"\n✓ Modified {modified_count} files")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze and manage valueless APIs in conti-benchmark YAML files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze and generate JSON report
  python3 api_analyzer.py --analyze --output report.json

  # Analyze and remove valueless APIs (with confirmation)
  python3 api_analyzer.py --analyze --remove

  # Dry-run removal (preview without modifying)
  python3 api_analyzer.py --analyze --remove --dry-run

  # Specify custom benchmark directory
  python3 api_analyzer.py --analyze --dir /path/to/benchmark
        """
    )
    
    parser.add_argument(
        '--analyze', '-a',
        action='store_true',
        help='Analyze YAML files for valueless APIs'
    )
    
    parser.add_argument(
        '--remove', '-r',
        action='store_true',
        help='Remove valueless APIs from YAML files (requires --analyze)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview removal without modifying files (use with --remove)'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='api_analysis_report.json',
        help='Output JSON file path (default: api_analysis_report.json)'
    )
    
    parser.add_argument(
        '--dir', '-d',
        type=str,
        help='Benchmark directory path (default: auto-detect)'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.analyze and not args.remove:
        parser.print_help()
        return
    
    if args.remove and not args.analyze:
        print("Error: --remove requires --analyze")
        return
    
    # Determine base directory
    if args.dir:
        base_dir = Path(args.dir)
    else:
        # Auto-detect: assume script is in utils/ subdirectory
        base_dir = Path(__file__).parent.parent
    
    if not base_dir.exists():
        print(f"Error: Directory not found: {base_dir}")
        return
    
    print("=" * 80)
    print("API Analyzer for conti-benchmark")
    print("=" * 80)
    print(f"Benchmark directory: {base_dir}\n")
    
    # Run analysis
    if args.analyze:
        results, statistics = analyze_all_yamls(base_dir)
        
        # Print summary
        print("\n" + "=" * 80)
        print("Analysis Summary")
        print("=" * 80)
        print(f"Total projects: {statistics['total_projects']}")
        print(f"Total APIs: {statistics['total_apis']}")
        print(f"Valueless APIs: {statistics['valueless_apis']} ({statistics['valueless_percentage']}%)")
        print(f"Valuable APIs: {statistics['valuable_apis']} ({100 - statistics['valueless_percentage']:.2f}%)")
        
        # Generate JSON report
        output_path = base_dir / args.output
        generate_json_report(results, statistics, output_path)
        
        # Remove valueless APIs if requested
        if args.remove:
            remove_valueless_apis(results, base_dir, dry_run=args.dry_run)
    
    print("\n" + "=" * 80)
    print("Done!")
    print("=" * 80)


if __name__ == '__main__':
    main()

