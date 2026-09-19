"""AgentGuard CLI entrypoint.

Usage:
    python -m agentguard llm health
"""

import sys
import json


def cli_llm_health():
    """Run AI Secura Ollama health check and print results."""
    from agentguard.llm_config import LLMConfig
    from agentguard.integrations.ollama_adapter import OllamaAISecuraAdapter

    config = LLMConfig.from_env()
    if not config.is_ollama:
        config = config.model_copy(update={"provider": "ollama"})

    print(f"AgentGuard AI Secura Health Check")
    print(f"=" * 50)
    print(f"Provider:  {config.provider}")
    print(f"Model:     {config.model}")
    print(f"Endpoint:  {config.ollama_base_url}")
    print()

    adapter = OllamaAISecuraAdapter(config)
    result = adapter.health_check()

    checks = [
        ("Ollama Reachable", result["ollama_reachable"]),
        ("Model Exists", result["model_exists"]),
        ("Model Responds", result["model_responds"]),
        ("JSON Valid", result["json_valid"]),
        ("Schema Valid", result["schema_valid"]),
    ]

    for label, status in checks:
        icon = "PASS" if status else "FAIL"
        print(f"  [{icon}]  {label}")

    print()
    print(f"Details: {result.get('details', 'N/A')}")

    all_pass = all(s for _, s in checks)
    print()
    if all_pass:
        print("Result: ALL CHECKS PASSED")
    else:
        print("Result: SOME CHECKS FAILED")

    return 0 if all_pass else 1


def main():
    args = sys.argv[1:]

    if len(args) >= 2 and args[0] == "llm" and args[1] == "health":
        sys.exit(cli_llm_health())
    elif len(args) >= 1 and args[0] == "version":
        print("agentguard 0.3.5")
    else:
        print("Usage:")
        print("  python -m agentguard llm health   — Check Ollama connectivity")
        print("  python -m agentguard version       — Show version")
        sys.exit(1)


if __name__ == "__main__":
    main()
