"""
Merge two experiment result reports for result comparison.
A result report is a CSV format of:
  https://llm-exp.oss-fuzz.com/report-ochang-20230809/
"""
import argparse
import os

import pandas as pd

def extract_basename_from_filename(filename):
  """
  Extract the basename from the filename.

  Args:
  - filename (str): The name of the file.

  Returns:
  - str: The extracted basename.
  """
  return os.path.basename(os.path.splitext(filename)[0])

def merge_tables(file1, file2):
  """
  Merge, compare, and sort two CSV tables based on the benchmark name and build
  rate differences.

  Args:
  - file1 (str): Path to the first CSV file.
  - file2 (str): Path to the second CSV file.

  Returns:
  - DataFrame: The merged, compared, and sorted table.
  """
  basename1 = extract_basename_from_filename(file1)
  basename2 = extract_basename_from_filename(file2)

  df1 = pd.concat((chunk for chunk in pd.read_csv(file1, chunksize=5000)))
  df2 = pd.concat((chunk for chunk in pd.read_csv(file2, chunksize=5000)))

  merged_df = df1.merge(df2,
                        on='Benchmark',
                        how='outer',
                        suffixes=(f'_{basename1}', f'_{basename2}'))

  # Fill NaN values with '-' and convert columns to string type
  for col in merged_df.columns:
    merged_df[col] = merged_df[col].fillna('-').astype(str)

  # Calculate build rate differences for sorting
  merged_df['build_rate_diff'] = merged_df.apply(
      lambda row: abs(
          float(row[f'Build rate_{basename1}']) - float(row[
              f'Build rate_{basename2}']))
      if row[f'Build rate_{basename1}'] != '-' and row[f'Build rate_{basename2}'
                                                      ] != '-' else 0,
      axis=1)

  # Sorting criteria
  merged_df['sort_diff'] = merged_df['build_rate_diff'].apply(lambda x: 0
                                                              if x == 0 else 1)
  merged_df['sort_non_zero'] = merged_df.apply(
      lambda row: 1 if (row[f'Build rate_{basename1}'] != '0' or row[
          f'Build rate_{basename2}'] != '0') and row[f'Build rate_{basename1}']
      != '-' and row[f'Build rate_{basename2}'] != '-' else 0,
      axis=1)
  merged_df['sort_zero'] = merged_df.apply(
      lambda row: 1 if row[f'Build rate_{basename1}'] == '0' and row[
          f'Build rate_{basename2}'] == '0' else 0,
      axis=1)
  merged_df['sort_missing'] = merged_df.apply(
      lambda row: 1 if row[f'Build rate_{basename1}'] == '-' or row[
          f'Build rate_{basename2}'] == '-' else 0,
      axis=1)
  merged_df['sort_basename'] = merged_df.apply(
      lambda row: 1 if row[f'Build rate_{basename1}'] == '-' and row[
          f'Build rate_{basename2}'] != '-' else 0,
      axis=1)

  merged_df.sort_values(by=[
      'sort_diff', 'build_rate_diff', 'sort_non_zero', 'sort_zero',
      'sort_missing', 'sort_basename'
  ],
                        ascending=[False, False, False, False, True, True],
                        inplace=True)
  merged_df.drop(columns=[
      'sort_diff', 'sort_non_zero', 'sort_zero', 'sort_missing',
      'sort_basename', 'build_rate_diff'
  ],
                 inplace=True)

  columns_order = [
      'Benchmark', 'Status_' + basename1, 'Status_' + basename2,
      'Build rate_' + basename1, 'Build rate_' + basename2,
      'Crash rate_' + basename1, 'Crash rate_' + basename2,
      'Coverage_' + basename1, 'Coverage_' + basename2,
      'Line coverage diff_' + basename1, 'Line coverage diff_' + basename2
  ]
  merged_df = merged_df[columns_order]

  return merged_df

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description=(
      'Merge, compare, and sort two CSV tables based on the benchmark name and '
      'build rate differences.'))
  parser.add_argument('file1', type=str, help='Path to the first CSV file.')
  parser.add_argument('file2', type=str, help='Path to the second CSV file.')

  args = parser.parse_args()

  output_df = merge_tables(args.file1, args.file2)

  input_basename2 = extract_basename_from_filename(args.file2)
  output_filename = f'{input_basename2}_merged.csv'
  output_df.to_csv(output_filename, index=False)
  print(f'Output saved to {output_filename}')
