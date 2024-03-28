import json
import os
import re
import sys

import yaml

from clang_diag import DiagGroup, Diagnostic, TextSubstitution


class _DiagRegexBuilder:

  def __init__(self, diag: str):
    # Raw diag text.
    self.diag = diag
    # Temp storage for concatenating regex string when finished.
    self._char_list = list()
    # args_count stores the number of capturing group in the regex,
    # which is the number of %[0-9] in diag.
    self.args_count = 0

  def get_regex(self) -> tuple[str, int]:
    substituted_diag = self._do_substitution()
    try:
      self._walkthrough_diag(substituted_diag)
    except IndexError:
      raise ValueError(f'Incomplete format {self.diag}')
    regex = ''.join(self._char_list)
    try:
      re.compile(regex)
    except re.error as e:
      print(f'Error compiling regex:\n{regex}')
      print(f'Diagnostic text:\n{self.diag}')
      print(e)
    return regex, self.args_count

  def _do_substitution(self) -> str:
    diag = self.diag
    sub_search = re.compile(r'%sub\{(.+?)\}\d(?:,\d)*')  # %sub{...}0,...
    substitution = sub_search.search(diag)
    while substitution:
      sub_string = substitution.group(0)
      sub_name = substitution.group(1)
      text_substitution = text_substitutions.get(sub_name)
      if not text_substitution:
        raise ValueError(f'TextSubstitution {sub_name} does not exist')
      # Don't care about actual args order, replace as is.
      diag = diag.replace(sub_string, text_substitution.substitution)
      substitution = sub_search.search(diag)
    return diag

  def _walkthrough_diag(self, diag: str):
    ptr = 0
    while ptr < len(diag):
      ch = diag[ptr]
      if ch in r'\^$.|?*+()[]{}':  # regex special chars
        self._char_list.extend('\\' + ch)
      elif ch == '%':
        ptr += self._parse_formatter(diag[ptr:])
      else:
        self._char_list.extend(ch)
      ptr += 1

  def _parse_formatter(self, diag: str) -> int:
    ptr = 1
    ch = diag[ptr]
    if ch in '%:$|[]}':  # escaped format char
      if ch in '$|[]}':  # regex special chars
        self._char_list.extend('\\')
      self._char_list.extend(ch)
      return ptr
    if ch.isdigit():  # %[0-9]
      self.args_count += 1
      self._char_list.extend('(.*)')
      return ptr

    find_specifier = re.match(r'%(\w+?)(?={|\d)', diag)
    if not find_specifier:
      raise ValueError(f'Unexpected formatter at the beginning of {diag}')
    specifier = find_specifier.group(1)
    ptr = find_specifier.span()[1]

    if specifier == 's':  # %s0
      if not diag[ptr].isdigit():
        raise ValueError(
            f'Unexpected char "{ch}" after "%{specifier}" format in {diag}')
      self._char_list.extend('s?')
      return ptr
    # %objcclass0, %objcinstance0, %q0
    if specifier == 'objcclass' or specifier == 'objcinstance' or specifier == 'q':
      if not diag[ptr].isdigit():
        raise ValueError(
            f'Unexpected char "{ch}" after "%{specifier}" format in {diag}')
      self.args_count += 1
      self._char_list.extend('(.*)')
      return ptr
    if specifier == 'ordinal':  # %ordinal0
      if not diag[ptr].isdigit():
        raise ValueError(
            f'Unexpected char "{ch}" after "%{specifier}" format in {diag}')
      self._char_list.extend('\\d+(?:st|nd|rd|th)')
      return ptr

    if not diag[ptr] == '{':
      raise ValueError(
          f'Unexpected char "{ch}" after "%{specifier}" format in {diag}')
    end_of_bracket = ptr + self._find_end_of_bracket(diag[ptr:])
    self._char_list.extend('(?:')
    ptr += 1

    if specifier == 'select':  # %select{...|...}0
      if not diag[end_of_bracket].isdigit():
        raise ValueError(
            f'Unexpected char "{diag[end_of_bracket]}" at the end of "%{specifier}" format in {diag}'
        )
      while ptr < end_of_bracket - 1:
        sep_ptr = ptr + self._find_first_bar(diag[ptr:end_of_bracket - 1])
        self._walkthrough_diag(diag[ptr:sep_ptr])
        ptr = sep_ptr
        if diag[ptr] == '|':
          self._char_list.extend('|')
          ptr += 1
      self._char_list.extend(')')
      return end_of_bracket

    if specifier == 'plural':  # %plural{(%100=)0:...|[1,2]:...|:...}0
      if not diag[end_of_bracket].isdigit():
        raise ValueError(
            f'Unexpected char "{diag[end_of_bracket]}" at the end of "%{specifier}" format in {diag}'
        )
      while ptr < end_of_bracket - 1:
        sep_ptr = ptr + self._find_first_bar(diag[ptr:end_of_bracket - 1])
        piece = diag[ptr:sep_ptr]
        text = piece[piece.index(':') + 1:]
        self._walkthrough_diag(text)
        ptr = sep_ptr
        if diag[ptr] == '|':
          self._char_list.extend('|')
          ptr += 1
      self._char_list.extend(')')
      return end_of_bracket

    if specifier == 'diff':  # %diff{...$...$...|...}0,1
      if not re.match(r'\d,\d', diag[end_of_bracket:end_of_bracket + 3]):
        raise ValueError(
            f'2 arguments not found at the end of "%{specifier}{{...}}{diag[end_of_bracket:end_of_bracket + 3]}" format in {diag}'
        )
      sep_ptr = ptr + self._find_first_bar(diag[ptr:end_of_bracket - 1])
      first_half = diag[ptr:sep_ptr]
      self._replace_dollar_in_current_diff(first_half)
      self._walkthrough_diag(first_half)
      ptr = sep_ptr

      self._char_list.extend('|')
      ptr += 1

      second_half = diag[ptr:end_of_bracket - 1]
      self._replace_dollar_in_current_diff(second_half)
      self._walkthrough_diag(second_half)
      self._char_list.extend(')')
      return end_of_bracket + 2

    raise ValueError(f'Unexpected format specifier "{specifier}" in {diag}')

  @staticmethod
  def _find_end_of_bracket(sub: str) -> int:
    if sub[0] != '{':
      raise ValueError(
          '_find_end_of_bracket() should be used on sub strings starting with "{"'
      )
    count = 1
    ptr = 1
    while count > 0:
      if sub[ptr] == '{':
        count += 1
      if sub[ptr] == '}':
        count -= 1
      ptr += 1
    return ptr

  @staticmethod
  def _find_first_bar(sub: str) -> int:
    ptr = 0
    bracket_level = 0
    while ptr < len(sub):
      ch = sub[ptr]
      if ch == '|' and bracket_level == 0:
        break
      if ch == '%':
        ptr += 1
      if ch == '{':
        bracket_level += 1
      if ch == '}':
        bracket_level -= 1
      ptr += 1
    return ptr

  @staticmethod
  def _replace_dollar_in_current_diff(sub: str) -> str:
    char_list = list()
    ptr = 0
    bracket_level = 0
    while ptr < len(sub):
      ch = sub[ptr]
      if ch == '{':
        bracket_level += 1
      if ch == '}':
        bracket_level -= 1

      if sub[ptr:ptr + 2] == '%$' and bracket_level == 0:
        char_list.extend('$')
        ptr += 1
      elif sub[ptr] == '$' and bracket_level == 0:
        char_list.extend('%0')
      else:
        char_list.extend(ch)

      ptr += 1
    return ''.join(char_list)


def _to_yaml(diagnostics: dict[str, Diagnostic], outdir: str = './'):
  result = dict()
  for raw_name in diagnostics.keys():
    diag = diagnostics[raw_name]
    result[raw_name] = {
        'CategoryName': diag.category_name,
        'Class': diag.diag_class,
        'Component': diag.component,
        'DefaultSeverity': diag.default_severity,
        'Group': str(diag.group),
        'SFINAE': diag.sfinae,
        'Text': diag.text,
        'Regex': diag.regex,
        'ArgsCount': diag.args_count,
    }
  with open(os.path.join(outdir, f'diag_regexes.yaml'), 'w') as file:
    yaml.dump(result, file, default_flow_style=False, width=sys.maxsize)


def from_yaml(yaml_path: str) -> dict[str, Diagnostic]:
  diagnostics = dict()
  with open(yaml_path, 'r') as yaml_file:
    data = yaml.safe_load(yaml_file)

  for raw_name in data.keys():
    diagnostic = data[raw_name]
    category_name = diagnostic.get('CategoryName', '')
    diag_class = diagnostic.get('Class', '')
    component = diagnostic.get('Component', '')
    default_severity = diagnostic.get('DefaultSeverity', '')
    group = diagnostic.get('Group', '')
    sfinae = diagnostic.get('SFINAE', '')
    text = diagnostic.get('Text', '')
    regex = diagnostic.get('Regex', '')
    args_count = diagnostic.get('ArgsCount', 0)
    diagnostics[raw_name] = Diagnostic(category_name, diag_class, component,
                                       default_severity, group, sfinae, text,
                                       regex, args_count)
  return diagnostics


def main():
  # Generated with:
  # llvm-tblgen -dump-json -o Diagnostic.json \
  # -I llvm/clang/include/clang/Basic \
  # llvm/clang/include/clang/Basic/Diagnostic.td
  # TODO: Use argparse to specify json file path.
  with open('Diagnostic.json', 'r') as json_f:
    raw_diag_obj = json.load(json_f)

  class_def = raw_diag_obj.get('!instanceof')
  diag_group_name = class_def.get('DiagGroup')
  text_substitution_name = class_def.get('TextSubstitution')
  diagnostic_name = class_def.get('Diagnostic')

  # Parse diag groups.
  diag_groups = {}
  for raw_name in diag_group_name:
    diag_group = raw_diag_obj.get(raw_name)
    category_name = diag_group.get('CategoryName', '')
    documentation = diag_group.get('Documentation', '')
    group_name = diag_group.get('GroupName', raw_name)
    sub_groups = diag_group.get('SubGroups', [])
    diag_groups[raw_name] = DiagGroup(category_name, documentation, group_name,
                                      sub_groups)

  # Parse text substitutions.
  for raw_name in text_substitution_name:
    text_sub = raw_diag_obj.get(raw_name)
    category_name = text_sub.get('CategoryName', '')
    component = text_sub.get('Component', '')
    substitution = text_sub.get('Substitution', '')
    text_substitutions[raw_name] = TextSubstitution(category_name, component,
                                                    substitution)

  # Parse diagnostics.
  diagnostics = {}
  for raw_name in diagnostic_name:
    diagnostic = raw_diag_obj.get(raw_name)
    category_name = diagnostic.get('CategoryName', '')
    diag_class = diagnostic.get('Class', {})
    diag_class_name = diag_class.get('def', '') if diag_class else ''
    component = diagnostic.get('Component', '')
    default_severity = diagnostic.get('DefaultSeverity', {})
    default_severity_name = default_severity.get('def',
                                                 '') if default_severity else ''
    group = diagnostic.get('Group', {})
    diag_group = diag_groups.get(group.get('def', '')) if group else None
    sfinae = diagnostic.get('SFINAE', {})
    sfinae_name = sfinae.get('def', '') if sfinae else ''
    text = diagnostic.get('Text', '')

    if not text or text == '%0':  # Skip empty or arbitrary diagnostics.
      continue
    diagnostic = Diagnostic(category_name, diag_class_name, component,
                            default_severity_name, diag_group, sfinae_name,
                            text)
    drb = _DiagRegexBuilder(diagnostic.text)
    diagnostic.regex, diagnostic.args_count = drb.get_regex()
    diagnostics[raw_name] = diagnostic
    print(f'Parsed {raw_name}')

    _to_yaml(diagnostics)


if __name__ == '__main__':
  text_substitutions = {}  # Global for use when generating diag regex.
  main()
