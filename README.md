# mcp-vscode-template
MCP server template for VS Code Agent   

###  Setup  
Install uv however you like. May options available.  
https://docs.astral.sh/uv/getting-started/installation/  

Project setup is heavily based off of Renae Schilg's work. I didn't even bother to change the project name as an homage although I did deviate on a few things, namely not using Claude Desktop, but also modified `external-recon.py` fairly heavily.  
https://nae-bo.medium.com/building-your-first-offensive-security-mcp-server-dd655e258d5f  

```bash
# Initialize project
uv init external-recon
cd external-recon
```

I had to modify the python versions in `.python-version` to `3.11` or something above 3.8 or 3.10  
I also had to modify the line `requires-python = ">=3.11"` in `pyroject.toml` to something above 3.8 or 3.10
Mileage will vary... It may not be necessary.  

```bash
# Create virtual environment and activate it
uv venv --python 3.11
source .venv/bin/activate

# Install mcp
uv add "mcp[cli]"

# Create MCP server .py file
touch external-recon.py
```

The VS Code `settings.json` should be modified.  
Use `which uv` to find the path to uv.  
The `"/path/to/project/external-recon"` should refer to the project path, where the MCP server .py file is located (use absoulte path).  

settings.json
```json
    "mcp": {
        "servers": {
                "external-recon": {
                 "command": "/path/to/uv",
                 "args": [
                  "--directory",
                  "/path/to/project/external-recon",
                  "run",
                  "external-recon.py"
                 ]
                }
        }
    },
```

One of the main differences between Renae's work and mine is I used `@mcp.tool()` instead of `@mcp.prompt()` in `external-recon.py`

From the venv of the project, start the server with `uv run external-recon.py`  
Example:  
```bash
(external-recon) user@workstation external-recon % uv run external-recon.py
```
