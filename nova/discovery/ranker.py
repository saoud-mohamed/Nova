class ParameterRanker:

    HIGH_SIGNAL = {
        "id",
        "uid",
        "user_id",
        "userid",
        "account_id",
        "email",
        "username",
        "user",
        "query",
        "q",
        "search",
        "page",
        "limit",
        "offset",
        "sort",
        "order",
        "file",
        "path",
        "url",
        "redirect",
        "next",
        "return",
        "callback",
    }

    MEDIUM_SIGNAL = {
        "name",
        "type",
        "category",
        "lang",
        "token",
        "key",
        "value",
        "action",
        "format",
    }

    @classmethod
    def score(cls, parameter: str) -> int:

        name = parameter.lower().strip()

        if name in cls.HIGH_SIGNAL:
            return 100

        if name in cls.MEDIUM_SIGNAL:
            return 60

        if name.endswith("_id"):
            return 85

        if name.startswith("id_"):
            return 80

        if "email" in name:
            return 90

        if "user" in name:
            return 75

        if "token" in name:
            return 70

        return 10

    @classmethod
    def rank(
        cls,
        parameters: list[str],
    ) -> list[str]:

        unique = list(
            dict.fromkeys(
                parameter.strip()
                for parameter in parameters
                if parameter.strip()
            )
        )

        return sorted(
            unique,
            key=lambda item: (
                -cls.score(item),
                item.lower(),
            ),
        )