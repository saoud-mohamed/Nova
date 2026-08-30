from pathlib import Path


class PayloadLoader:

    def load(self, wordlist: str) -> list[str]:

        path = Path(wordlist)

        if not path.exists():
            raise FileNotFoundError(
                f"Payload wordlist not found: {wordlist}"
            )

        if not path.is_file():
            raise ValueError(
                f"Not a file: {wordlist}"
            )

        payloads = []

        with path.open(
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            for line in file:

                payload = line.strip()

                if not payload:
                    continue

                if payload.startswith("#"):
                    continue

                payloads.append(payload)

        return list(dict.fromkeys(payloads))