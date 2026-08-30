import re


class DynamicContent:

    UUID_RE = re.compile(
        r"\b[0-9a-fA-F]{8}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{12}\b"
    )

    HEX_RE = re.compile(
        r"\b(?=[0-9a-fA-F]{16,}\b)"
        r"(?=[0-9a-fA-F]*[a-fA-F])"
        r"[0-9a-fA-F]+\b"
    )

    LONG_NUMBER_RE = re.compile(
        r"\b\d{6,}\b"
    )

    SPACE_RE = re.compile(
        r"\s+"
    )

    def normalize(self, text: str) -> str:

        if not text:
            return ""

        text = self.UUID_RE.sub(
            "<NOVA_UUID>",
            text,
        )

        text = self.HEX_RE.sub(
            "<NOVA_HEX>",
            text,
        )

        text = self.LONG_NUMBER_RE.sub(
            "<NOVA_NUMBER>",
            text,
        )

        text = self.SPACE_RE.sub(
            " ",
            text,
        )

        return text.strip()