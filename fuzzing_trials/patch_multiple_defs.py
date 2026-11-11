import sys
import os
import re
import subprocess as sp


RE = re.compile(r"multiple definition of `([^('']+)")

def extract_multiple_defs(build_log: str) -> list[str]:
    with open(build_log, "r") as f:
        return set(RE.findall(f.read()))

if __name__ == "__main__":
    if not len(sys.argv) == 4:
        print(f"Usage: {sys.argv[0]} <library_name> <build_log> <approach>")
    library_name = sys.argv[1]
    build_log = sys.argv[2]
    appr = sys.argv[3]

    funcs_defined_multiple_times = extract_multiple_defs(build_log)
    for name in funcs_defined_multiple_times:
        pattern = rf'{name}\s*\([^)]*\)\s*\{{'

        find_definitions_cmd = [
            "grep",
            "-R", "-l", "-P", "-z",
            pattern,
            f"fuzzing_trials/target_src/{library_name}/{appr}"
        ]

        print(" ".join(find_definitions_cmd))

        proc = sp.run(find_definitions_cmd, stdout=sp.PIPE, stderr=sp.PIPE, text=True)

        files = proc.stdout.split("\n")
        for filename in files:
            if not filename:
                continue
            file_num = os.path.basename(filename).split(".")[0]
            rewrite_def_cmd = [
                "sed",
                "-i",
                f"s|{name}|{name}_{file_num}|",
                filename
            ]
            proc = sp.run(rewrite_def_cmd, stdout=sp.PIPE, stderr=sp.PIPE, text=True)
