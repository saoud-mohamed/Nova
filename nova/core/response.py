from dataclasses import dataclass, field
from typing import Dict


@dataclass
class ResponseData:

    url: str

    status: int

    body: str

    headers: Dict[str, str] = field(
        default_factory=dict
    )

    elapsed_ms: float = 0.0

    content_length: int = 0

    words: int = 0

    lines: int = 0

    error: str | None = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    @property
    def is_redirect(self) -> bool:
        return self.status in {
            301,
            302,
            303,
            307,
            308,
        }

    @property
    def location(self) -> str | None:

        for key, value in self.headers.items():

            if key.lower() == "location":
                return value

        return None