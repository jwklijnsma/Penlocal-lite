# Install (real models)

```bash
cd penlocal-lite
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# host your models locally
ollama serve &
ollama pull qwen3:8b
ollama pull llama3.1:8b        # a different family for the verifier
```
