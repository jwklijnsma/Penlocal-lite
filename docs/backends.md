# Backends

| Backend | Use it for | Set with |
|---|---|---|
| `ollama` (default) | local models via [Ollama](https://ollama.com) | `backend: ollama` |
| `openai-compat` | vLLM, `llama.cpp --server`, LM Studio, TGI | `backend: openai-compat`, `api_base` |
| `mock` | offline demos & tests | `--backend mock` |

All three satisfy the same tiny interface, so any role can point at any
backend/model — and all can be kept fully local.
