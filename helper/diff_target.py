"""
Replace the fuzz target binary name (`target_name`) in all benchmark YAMLs of a
dir with the target name of the corresponding YAMLs of another dir. Target will
only be replaced if they share the same fuzz target source code path
(`target_path`).
Usage: python3 diff_target.py <dest-dir> <source-dir>
"""
import argparse
import os

import yaml


def load_yaml(file_path):
  """Load a YAML file and return its contents."""
  try:
    with open(file_path, 'r') as f:
      return yaml.safe_load(f)
  except Exception as e:
    print(f"Error loading YAML file {file_path}: {e}")
    return None


def save_yaml(file_path, data):
  """Save a dictionary to a YAML file."""
  try:
    with open(file_path, 'w') as f:
      yaml.safe_dump(data, f)
  except Exception as e:
    print(f"Error saving YAML file {file_path}: {e}")


def overwrite_target_name(dir_a, dir_b):
  """Overwrite target_name in A if target_path is the same and target_name differs."""
  common_files = set(os.listdir(dir_a)) & set(os.listdir(dir_b))
  updated_files = []

  for file_name in common_files:
    if not file_name.endswith('.yaml'):
      continue

    file_a = os.path.join(dir_a, file_name)
    file_b = os.path.join(dir_b, file_name)

    data_a = load_yaml(file_a)
    data_b = load_yaml(file_b)

    if data_a and data_b:
      if data_a.get('target_path') == data_b.get('target_path'):
        if data_a.get('target_name') != data_b.get('target_name'):
          data_a['target_name'] = data_b['target_name']
          save_yaml(file_a, data_a)
          updated_files.append(file_name)

  return updated_files


if __name__ == "__main__":
  parser = argparse.ArgumentParser(
      description="Update target_name in A if target_path matches B.")
  parser.add_argument("dir_a", help="Path to directory A (to be updated)")
  parser.add_argument("dir_b", help="Path to directory B (source of updates)")
  args = parser.parse_args()

  updated_files = overwrite_target_name(args.dir_a, args.dir_b)
  if updated_files:
    print("The following files in A had target_name updated from B:")
    for file_name in updated_files:
      print(file_name)
  else:
    print("No updates were necessary.")
