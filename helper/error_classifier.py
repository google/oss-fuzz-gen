import re
import yaml

class BuildErrorClassifier:
    def __init__(self, error_db_path: str):
        with open(error_db_path, 'r') as f:
            self.error_db = yaml.safe_load(f)

    def classify(self, compile_log: str) -> dict | None:
        for error_type, data in self.error_db.items():
            for pattern in data.get("patterns", []):
                if re.search(pattern, compile_log, re.IGNORECASE):
                    return {
                        "type": error_type,
                        "good": data.get("good", []),
                        "bad": data.get("bad", []),
                    }
        return None

    def _find_first_error_msg(self, compile_log: str) -> str | None:
        match = re.search(r"<stderr>(.*?)</stderr>", compile_log, re.DOTALL)
        if match:
            compile_log = match.group(1).strip()
        else:
            return None

        lines = compile_log.splitlines()
        for i, line in enumerate(lines):
            if any(kw in line.lower() for kw in ('error:', 'fatal error', 'undefined reference')):
                return '\n'.join(lines[i:])
        return None

    def trim_and_classify_err_msg(self, compile_log:str) -> dict | None:
        compile_log = self._find_first_error_msg(compile_log)
        if not compile_log:
            return None
        for error_type, data in self.error_db.items():
            for pattern in data.get("patterns", []):
                try:
                    match = re.search(pattern, compile_log, re.IGNORECASE)
                except Exception:
                    print(f"Error with pattern: {pattern}")
                    continue
                if match:
                    return {
                        "type": error_type,
                        "trimmed_msg": compile_log.strip()}
        return {
            "type": "unknown",
            "trimmed_msg": compile_log.strip()}

