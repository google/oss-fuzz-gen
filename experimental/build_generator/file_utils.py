import os
from typing import List, Optional

try:
  # For execution outside of a docker container
  from experimental.build_generator import templates
except (ImportError, SystemError):
  # For execution inside of a docker container
  import templates


def determine_project_language(path: str) -> str:
  """Returns the likely language of a project by looking at file suffixes."""
  all_files = get_all_files_in_path(path, path)

  language_dict = {'c': 0, 'c++': 0}
  for source_file in all_files:
    if source_file.endswith('.c'):
      language_dict['c'] = language_dict['c'] + 1
    elif source_file.endswith('.cpp'):
      language_dict['c++'] = language_dict['c++'] + 1
    elif source_file.endswith('.cc'):
      language_dict['c++'] = language_dict['c++'] + 1

  target_language = 'c++'
  max_count = 0
  for language, count in language_dict.items():
    if count > max_count:
      target_language = language
      max_count = count
  return target_language


def get_language_defaults(language: str):
  compilers_and_flags = {
      'c': ('$CC', '$CFLAGS', '/src/empty-fuzzer.c', templates.C_BASE_TEMPLATE),
      'c++': ('$CXX', '$CXXFLAGS', '/src/empty-fuzzer.cpp',
              templates.CPP_BASE_TEMPLATE),
  }
  return compilers_and_flags[language]


def get_all_files_in_path(base_path: str,
                          path_to_subtract: Optional[str] = None) -> List[str]:
  """Gets all files in a tree and returns as a list of strings."""
  all_files = []
  if path_to_subtract is None:
    path_to_subtract = os.getcwd()
  for root, _, files in os.walk(base_path):
    for fi in files:
      path = os.path.join(root, fi)
      if path.startswith(path_to_subtract):
        path = path[len(path_to_subtract):]
      if len(path) > 0 and path[0] == '/':
        path = path[1:]
      all_files.append(path)
  return all_files
