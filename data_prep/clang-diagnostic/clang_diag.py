class DiagGroup:

  def __init__(self, category_name: str, documentation: str, group_name: str,
               sub_groups: list[str]):
    self.category_name = category_name
    self.documentation = documentation
    self.group_name = group_name
    self.sub_groups = sub_groups

  def __str__(self):
    return self.group_name


class TextSubstitution:

  def __init__(self, category_name: str, component: str, substitution: str):
    self.category_name = category_name
    self.component = component
    self.substitution = substitution

  def __str__(self):
    return self.substitution


class Diagnostic:

  def __init__(self,
               category_name: str,
               diag_class: str,
               component: str,
               default_severity: str,
               group: DiagGroup,
               sfinae: str,
               text: str,
               regex: str = '',
               args_count: int = 0):
    self.category_name = category_name
    self.diag_class = diag_class
    self.component = component
    self.default_severity = default_severity
    self.group = group
    self.sfinae = sfinae
    self.text = text
    self.regex = regex
    self.args_count = args_count

  def __str__(self):
    return self.text
