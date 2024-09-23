import json
from importlib import resources
import os

loaded = False
headerjson = None

def __load_headerfiles():
    global loaded, headerjson
    try:
        #with resources.open_text('headerfiles.data', "headerfiles.json") as f:
        # 获取当前脚本文件的目录
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # 构造 data 目录下 headerfiles.json 文件的完整路径
        file_path = os.path.join(current_dir, 'data', 'headerfiles.json')

        # 打开并加载 JSON 文件
        with open(file_path, 'r', encoding='utf-8') as f:
            headerjson = json.load(f)

    except FileNotFoundError:
        print("ERROR: headerfiles.json not found")
        headerjson = {}
    loaded = True

def is_supported_proj(proj: str) -> bool:
    """
    API function `is_supported_proj`
      - Usage: Check if a projection is supported by the API.
      - Return value: True if the projection is supported, False otherwise.
    """
    global loaded, headerjson
    if not loaded:
        __load_headerfiles()
    return set(headerjson.keys())

def get_proj_headers(proj: str) -> list[str]:
    """
    API function `get_proj_headers`
      - Usage: Get the inferred headers for a specific project.
      - Return value: A list of inferred headers for the project, their orders also matter.
    """
    global loaded, headerjson
    if not loaded:
        __load_headerfiles()
    if proj not in headerjson:
        return []
    return headerjson[proj]["headers"]

def get_build_script(proj: str, install_dir: str) -> str:
    """
    API function `get_build_script`
      - Usage: Get the build script for a specific project supported in OSS-FUZZ.
      - Return value: The build script for the project.
    """
    global loaded, headerjson
    if not loaded:
        __load_headerfiles()
    
    script = [ "# Begin of build script from headerfiles" ]
    script.append(f"export HEADERFILES_CUSTOM_INSTALL_DIR=\"{install_dir}\"")
    if proj in headerjson:
        script.append(f"mkdir -p {install_dir}/include")
        script.append(f"mkdir -p {install_dir}/lib")

        # Initialize variables to avoid "unbound variable" errors
        script.append("export CFLAGS=\"${CFLAGS:-}\"")
        script.append("export CXXFLAGS=\"${CXXFLAGS:-}\"")
        script.append("export LDFLAGS=\"${LDFLAGS:-}\"")

        # Append new flags to existing ones if they are already set
        script.append(f"export CFLAGS=\"$CFLAGS -I{install_dir}/include\"")
        script.append(f"export CXXFLAGS=\"$CXXFLAGS -I{install_dir}/include\"")
        script.append(f"export LDFLAGS=\"$LDFLAGS -L{install_dir}/lib\"")

        # script.append(f"export CFLAGS=\" -I{install_dir}/include\" ")
        # script.append(f"export CXXFLAGS=\" -I{install_dir}/include\" ")
        # script.append(f"export LDFLAGS=\" -I{install_dir}/lib\" ")

        script.extend(headerjson[proj].get("build", []))
    script.append("# End of build script from headerfiles")

    return "\n".join(script) + "\n"
