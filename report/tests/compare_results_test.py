import os
import pandas as pd
import pytest

from report.compare_results import extract_basename_from_filename, merge_tables


def test_extract_basename_from_filename():
    # Standard CSV file
    assert extract_basename_from_filename('path/to/file.csv') == 'file'
    # Multiple extensions
    assert extract_basename_from_filename('another.ext1.ext2.txt') == 'another.ext1.ext2'
    # No extension
    assert extract_basename_from_filename('no_ext') == 'no_ext'


def test_merge_tables(tmp_path):
    # Create first CSV file (basename 'a')
    df1 = pd.DataFrame({
        'Benchmark': ['bench1', 'bench2'],
        'Status': ['OK', 'FAIL'],
        'Build rate': [10, 5],
        'Crash rate': [0.1, 0.2],
        'Coverage': [80, 85],
        'Line coverage diff': [5, 10],
    })
    file1 = tmp_path / 'a.csv'
    df1.to_csv(file1, index=False)

    # Create second CSV file (basename 'b')
    df2 = pd.DataFrame({
        'Benchmark': ['bench1', 'bench3'],
        'Status': ['OK2', 'FAIL2'],
        'Build rate': [12, 0],
        'Crash rate': [0.1, 0.3],
        'Coverage': [82, 90],
        'Line coverage diff': [6, 15],
    })
    file2 = tmp_path / 'b.csv'
    df2.to_csv(file2, index=False)

    merged = merge_tables(str(file1), str(file2))

    # Expected column order
    expected_cols = [
        'Benchmark', 'Status_a', 'Status_b',
        'Build rate_a', 'Build rate_b',
        'Crash rate_a', 'Crash rate_b',
        'Coverage_a', 'Coverage_b',
        'Line coverage diff_a', 'Line coverage diff_b'
    ]
    assert merged.columns.tolist() == expected_cols

    # Expected sorted benchmarks: bench1(diff=2), bench2(missing b), bench3(missing a)
    assert merged['Benchmark'].tolist() == ['bench1', 'bench2', 'bench3']

    # Check fill of missing values
    row2 = merged[merged['Benchmark'] == 'bench2'].iloc[0]
    assert row2['Status_b'] == '-'
    assert row2['Build rate_b'] == '-'

    row3 = merged[merged['Benchmark'] == 'bench3'].iloc[0]
    assert row3['Status_a'] == '-'
    assert row3['Build rate_a'] == '-'

    # Validate numeric values carried through as strings
    row1 = merged[merged['Benchmark'] == 'bench1'].iloc[0]
    assert row1['Build rate_a'] == '10.0' or row1['Build rate_a'] == '10'
    assert row1['Build rate_b'] == '12.0' or row1['Build rate_b'] == '12'
