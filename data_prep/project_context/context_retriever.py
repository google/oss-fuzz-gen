import json
import os
import re
import shutil
import subprocess
import uuid
from collections import defaultdict
from typing import List, Tuple

from google.cloud import storage


class ContextRetriever:
  """ContextRetriever attempts to retrieve context for a certain project/function from ASTs."""
  BUILTIN_TYPES = [
      'int', 'int8_t', 'int16_t', 'int32_t', 'int64_t', 'uint8_t', 'uint16_t',
      'uint32_t', 'uint64_t', 'char', 'bool', 'long', 'short', 'size_t', 'void'
  ]

  AST_BASE_PATH = 'gs://oss-fuzz-experiment/_project_asts/_succeed'

  DOWNLOAD_TO_PATH = 'oss-fuzz-data/asts'

  OSS_FUZZ_EXP_BUCKET = 'oss-fuzz-llm-public'

  def __init__(self, project_name: str, function_signature: str):
    self._record_decl_nodes = defaultdict(list)
    self._typedef_decl_nodes = defaultdict(list)
    self._enum_decl_nodes = defaultdict(list)
    self._project_name = project_name
    self._function_signature = function_signature
    self._download_from_path = f'{self.AST_BASE_PATH}/{self._project_name}/*'
    self._uuid = uuid.uuid4()
    self._ast_path = os.path.join(self.DOWNLOAD_TO_PATH,
                                  f'{self._project_name}-{self._uuid}')

  def _get_function_name(self, target_function_signature: str) -> str:
    """Retrieves the function name from the target function signature."""
    # Grabs the function name by getting anything before '(' and then remove the type by grabbing any character after space.
    target_function = target_function_signature.split('(')[0].split(' ')[-1]
    # Removes possible pointer.
    target_function = target_function.replace('*', '')

    return target_function

  def _get_return_type(self, target_function_signature: str) -> str:
    """Retrieves the return type from the target function signature."""
    return ' '.join(target_function_signature.split('(')[0].split(' ')[:-1])

  def _get_function_params(self, target_function_signature: str) -> List[str]:
    """Retrieves the function parameters from the target function signature."""
    return target_function_signature.split('(')[1].split(')')[0].split(',')

  def _dequalify_and_get_info(self, target_type: str) -> Tuple[str, List[str]]:
    """Retrieves type information for each parameter."""
    dequal_type = self._get_dequal_type(target_type)

    if dequal_type in self.BUILTIN_TYPES:
      return '', []

    type_decl, complex_types = self._get_type(dequal_type)

    return type_decl, complex_types

  def _get_type_from_record_decl_node(self, ast_node) -> Tuple[str, list[str]]:
    """Gets a type from a specific RecordDecl node."""
    new_complex_types = set()

    inner_decls = ast_node.get('inner')
    tag_used = ast_node.get('tagUsed', '')
    decl_name = ' ' + ast_node.get('name', '') + ' '

    if inner_decls is None:
      return '', []

    contents = ''

    index = 0

    while index < len(inner_decls):
      # We search for FieldDecls and RecordDecls.
      # RecordDecls are searched for as structs/unions/etc can be defined in structs/unions/etc.
      inner_decl = inner_decls[index]
      index += 1

      kind = inner_decl.get('kind')
      if kind != 'FieldDecl' and kind != 'RecordDecl':
        continue

      if kind == 'FieldDecl':
        field_type = inner_decl.get('type').get('qualType')

        dequal_type = self._get_dequal_type(field_type)

        if dequal_type not in self.BUILTIN_TYPES:
          new_complex_types.add(field_type)

        field_name = inner_decl.get('name')
        contents += f'  {field_type} {field_name};\n'

      # TODO(ggryan@): Handle recursive RecordDecls.
      # Check to see if the next FieldDecl has a name or not.
      # In the case of a named RecordDecl, the next FieldDecl can be skipped.
    return f'{tag_used}{decl_name}{{\n{contents}}};', list(new_complex_types)

  def _get_type_from_record_decl(self,
                                 target_type: str) -> Tuple[str, list[str]]:
    """Retrieves type information from RecordDecl nodes."""
    for ast_node in self._record_decl_nodes[target_type]:
      type_info, new_types = self._get_type_from_record_decl_node(ast_node)

      if type_info == '':
        continue

      return type_info, new_types

    return '', []

  def _get_type_from_enum_decl(self, target_type: str) -> str:
    """Retrieves type information from EnumDecl nodes."""
    for ast_node in self._enum_decl_nodes[target_type]:
      field_decls = ast_node.get('inner', [])

      contents = ''

      for field_decl in field_decls:
        if field_decl.get('kind') != 'EnumConstantDecl':
          continue

        field_name = field_decl.get('name')
        field_parts = field_decl.get('inner', [])

        field_value = None

        for field_part in field_parts:
          field_kind = field_part.get('kind')

          if field_kind != 'ConstantExpr' and field_kind != 'ImplicitCastExpr':
            continue

          part_value = field_part.get('inner')[0]

          # Parts are sometimes wrapped as ImplicitCasts, then literals are wrapped by ConstantExprs.
          if part_value.get('inner') is None:
            field_value = part_value.get('value')
          else:
            field_value = part_value.get('inner')[0].get('value')

          break

        if field_value is None:
          contents += f'  {field_name},\n'
        else:
          contents += f'  {field_name} = {field_value},\n'

      return f'enum {target_type} {{\n{contents}\n}};'
    return ''

  def _get_type_from_typedef_decl(self, target_type: str) -> str:
    """Retrieves type information from TypedefDecl nodes."""
    ast_node = self._typedef_decl_nodes[target_type][0]
    qual_type = ast_node.get('type').get('qualType')

    # Check to see if typedef is to a function pointer.
    if '(' in qual_type:
      index = qual_type.find(')')
      return 'typedef ' + qual_type[:index] + target_type + qual_type[
          index:] + ';'
    # If not, construct typedef normally.
    else:
      return f'typedef {qual_type} {target_type};'

  # TODO(ggyran@) - Add support for UsingDecls, Unions and CxxRecordDecls.
  def _get_type(self, target_type: str) -> Tuple[str, list[str]]:
    """Retrieves target type information from nodes.
    Also, returns the list of complex types seen within target types."""
    if target_type in self._record_decl_nodes:
      return self._get_type_from_record_decl(target_type)

    if target_type in self._enum_decl_nodes:
      return self._get_type_from_enum_decl(target_type), []

    if target_type in self._typedef_decl_nodes:
      return self._get_type_from_typedef_decl(target_type), []

    return '', []

  def _get_dequal_type(self, fully_qualified_type: str) -> str:
    """For a given type, try and dequalify/strip it by removing cv-qualifiers, pointers etc.
    Enables types to be found by name, as tags such as union/struct and cv qualification are stored separately."""
    if fully_qualified_type == '':
      return ''

    tokens = fully_qualified_type.split(' ')

    tmp = []

    for token in tokens:
      item = token.replace('*', '')
      re.sub(r'\[[0-9]*\]', '', item)
      re.sub(r'\(\*\)', '', item)
      tmp.append(item)

    tokens = tmp

    if '' in tokens:
      tokens.remove('')

    if 'unsigned' in tokens:
      tokens.remove('unsigned')

    if 'const' in tokens:
      tokens.remove('const')

    if 'volatile' in tokens:
      tokens.remove('volatile')

    if 'struct' in tokens:
      tokens.remove('struct')

    # Only the unqualified type and identifier should exist here.
    if len(tokens) > 2:
      print(f'Error with extracting type: {tokens}')
      return ''

    if len(tokens) == 0:
      print(f'Type dequalifying failed: {fully_qualified_type}')
      return ''

    dequal_type = tokens[0]

    return dequal_type

  def _get_header_from_file(self, fully_qualified_path: str) -> str:
    """Searches a single AST to determine if the function signature can be found.
    Returns the file for the signature if found.
    Retrieve that node's loc->file to get the file where the FunctionDecl exists."""
    target_function = self._get_function_name(self._function_signature)

    with open(fully_qualified_path) as ast_file:
      ast_json = json.load(ast_file)
      # AST nodes are all wrapped in an inner node.
      ast_nodes = ast_json.get('inner', [])

      for num, ast_node in enumerate(ast_nodes):
        if ast_node.get('kind') != 'FunctionDecl' or ast_node.get(
            'name') != target_function:
          continue
        # If file is not there, search backwards for a node where file is defined.
        current_index = num
        while current_index > 0:
          search_node = ast_nodes[current_index]
          current_index -= 1
          if 'file' in search_node.get('loc'):
            return search_node.get('loc').get('file')

    return ''

  def retrieve_asts(self):
    """Downloads ASTs for the given project."""
    storage_client = storage.Client.create_anonymous_client()
    bucket = storage_client.bucket(self.OSS_FUZZ_EXP_BUCKET)
    project_prefix = os.path.join('project_asts', self._project_name)
    blobs = bucket.list_blobs(prefix=project_prefix)
    ast_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), self._ast_path))

    os.makedirs(ast_dir, exist_ok=True)

    for blob in blobs:
      file_relpath = blob.name.replace(f'{project_prefix}/', '')
      blob.download_to_filename(os.path.join(ast_dir, file_relpath))

  def cleanup_asts(self):
    """Removes ASTs for the given project."""
    shutil.rmtree(self._ast_path)

  def generate_lookups(self):
    """Goes through all AST files downloaded.
    Generates a lookup so that RecordDecl/TypedefDecl/EnumDecl nodes can be found by name."""
    for ast_file_path in os.listdir(self._ast_path):
      with open(f'{self._ast_path}/{ast_file_path}') as ast_file:
        try:
          ast_json = json.load(ast_file)
        # Files generated and uploaded are ocasionally empty.
        except Exception as e:
          print(e)
          continue

      ast_nodes = ast_json.get('inner', [])
      relevant_kinds = ['TypedefDecl', 'RecordDecl', 'EnumDecl']

      for ast_node in ast_nodes:
        ast_kind = ast_node.get('kind')
        node_name = ast_node.get('name')

        if ast_kind not in relevant_kinds:
          continue

        if ast_kind == 'TypedefDecl':
          self._typedef_decl_nodes[node_name].append(ast_node)
        elif ast_kind == 'RecordDecl':
          self._record_decl_nodes[node_name].append(ast_node)
        elif ast_kind == 'EnumDecl':
          self._enum_decl_nodes[node_name].append(ast_node)

  def get_header(self) -> str:
    """Goes through all AST files looking for a file where a FunctionDecl exists for the target function."""
    for ast_file_path in os.listdir(self._ast_path):
      try:
        header = self._get_header_from_file(f'{self._ast_path}/{ast_file_path}')
        if header != '':
          return header
      # ASTs from the bucket are ocasionally empty.
      except Exception as e:
        print(e)
        continue

    print(f'Header location could not be found for {self._function_signature}')
    return ''

  def get_type_info(self) -> List[str]:
    """Gets detailed information for types encountered in the target function."""
    types = []

    return_type = self._get_return_type(self._function_signature)
    return_type_decl, seen_types = self._dequalify_and_get_info(return_type)

    if return_type_decl != '':
      types.append(return_type_decl)

    # Retrieve types of params by removing the last token in a parameter (identifier).
    # TODO(ggryan): Sometimes there are symbols/declarations which only have a type and no identifier for params.
    params = self._get_function_params(self._function_signature)

    seen_types += [' '.join(param.split(' ')[:-1]) for param in params]

    # Recursively visit newly seen types.
    while seen_types:
      current_type = seen_types.pop()
      type_decl, new_types = self._dequalify_and_get_info(current_type)
      if type_decl == '' or type_decl in types:
        continue
      seen_types += new_types
      types.append(type_decl)

    return types
