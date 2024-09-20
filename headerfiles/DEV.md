# Dev Usage

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .[dev]
headerfiles-cli --help
#...
headerfiles-cli supp libpsl
headerfiles-cli infer libpsl
#...
pip uninstall headerfiles -y
```
