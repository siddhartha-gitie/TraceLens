
import requests


def test_ollama():
    url = "http://localhost:11434/api/chat"

    payload = {
        "model": "qwen2.5:3b",
        "messages": [
            {
                "role": "user",
                "content": (
                    "A database connection pool was reduced "
                    "from 20 to 5. Soon after, the service "
                    "started returning HTTP 503 errors. "
                    "Give a possible cause, the evidence available, "
                    "and one additional check needed to verify it."
                ),
            }
        ],
        "stream": False,
    }

    try:
        response = requests.post(url, json=payload, timeout=120)
        response.raise_for_status()

        result = response.json()
        print("\n--- TraceLens Ollama Test ---")
        print(result["message"]["content"])

    except requests.exceptions.ConnectionError:
        print("Could not connect to Ollama.")
        print("Make sure Ollama is running on your computer.")

    except requests.exceptions.RequestException as error:
        print(f"Request failed: {error}")


if __name__ == "__main__":
    test_ollama()
