"""Store benchmark information along with dataflows. 
Also provides common utility functions for harness generation"""
from __future__ import annotations

import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional
import yaml

from experiment.benchmark import Benchmark

# declare type classes: enum, fps, etc.
@dataclass
class Enum:
  name: str
  values: list[str]

  @classmethod
  def from_yaml(cls, benchmark_path: str) -> list:
    enums = []
    with open(benchmark_path, "r") as benchmark_file:
      data = yaml.safe_load(benchmark_file)
    if not data:
      return []

    enums_from_file = data.get("enums", [])
    for item in enums_from_file:
      enums.append(cls(name=item["name"], values=item["values"]))

    return enums


@dataclass
class Typedef:
  name: str
  datatype: str

  @classmethod
  def from_yaml(cls, benchmark_path: str) -> list:
    typedefs = []
    with open(benchmark_path, "r") as benchmark_file:
      data = yaml.safe_load(benchmark_file)
    if not data:
      return []

    typedefs_from_file = data.get("typedefs", [])
    for item in typedefs_from_file:
      typedefs.append(cls(name=item["name"], datatype=item["datatype"]))

    return typedefs


@dataclass
class FunctionPointer:
  name: str
  return_type: str
  signature: str

  @classmethod
  def from_yaml(cls, benchmark_path: str) -> list:
    fps = []
    with open(benchmark_path, "r") as benchmark_file:
      data = yaml.safe_load(benchmark_file)
    if not data:
      return []

    fps_from_file = data.get("function_pointers", [])
    for item in fps_from_file:
      fps.append(
          cls(name=item["name"],
              return_type=item["return_type"],
              signature=item["signature"]))

    return fps


class ProjectInfo:

  def __init__(self, functions: list[Benchmark], macros: list[str],
               enums: list[Enum], typedefs: list[Typedef],
               function_pointers: list[FunctionPointer]):
    self.functions = functions
    self.macros = macros
    self.enums = enums
    self.typedefs = typedefs
    self.function_pointers = function_pointers

  def get_benchmark_by_name(self, function_name: str) -> Optional[Benchmark]:
    """Given a function name, return the corresponding benchmark."""
    #TODO: Consider overloaded functions
    for bench in self.functions:
      if function_name == bench.function_name:
        return bench
    return None

  @classmethod
  def to_yaml(
      cls,
      benchmarks: list[Benchmark],
      macros: list[str],
      enums: list[Enum],
      typedefs: list[Typedef],
      function_pointers: list[FunctionPointer],
      outdir: str = "./",
      out_basename: str = "",
  ):
    """Converts and saves selected fields of a project to a YAML file."""
    # Register the custom representer
    result = Benchmark.to_yaml(benchmarks, dump_to_file=False)
    result["macros"] = []
    result["enums"] = []
    result["typedefs"] = []
    result["function_pointers"] = []
    for m in macros:
      result["macros"].append(m)
    for e in enums:
      result["enums"].append({"name": e.name, "values": e.values})
    for t in typedefs:
      result["typedefs"].append({"name": t.name, "datatype": t.datatype})
    for f in function_pointers:
      result["function_pointers"].append({
          "name": f.name,
          "return_type": f.return_type,
          "signature": f.signature
      })

    if not out_basename:
      out_basename = f"{benchmarks[0].project}.yaml"
    with open(os.path.join(outdir, out_basename), "w") as file:
      yaml.dump(result, file, default_flow_style=False, width=sys.maxsize)

  @classmethod
  def from_yaml(cls, benchmark_path: str) -> ProjectInfo:
    with open(benchmark_path, "r") as benchmark_file:
      data = yaml.safe_load(benchmark_file)
    if not data:
      return []
    benchmarks = Benchmark.from_yaml(benchmark_path)
    macros = data.get("macros", [])
    enums = Enum.from_yaml(benchmark_path)
    typedefs = Typedef.from_yaml(benchmark_path)
    function_pointers = FunctionPointer.from_yaml(benchmark_path)
    return cls(benchmarks, macros, enums, typedefs, function_pointers)