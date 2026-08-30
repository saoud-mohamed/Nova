class Wordlist:

    @staticmethod
    def load(path: str) -> list[str]:

        words = []

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            for line in file:

                word = line.strip()

                if not word:
                    continue

                if word.startswith("#"):
                    continue

                words.append(word)

        return list(
            dict.fromkeys(words)
        )