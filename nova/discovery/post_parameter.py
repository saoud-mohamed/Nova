class PostParameterDiscovery:

    def __init__(
        self,
        requester,
        engine,
        wordlist,
    ):
        self.requester = requester
        self.engine = engine

        self.wordlist = [
            word.strip()
            for word in wordlist
            if word.strip()
            and not word.startswith("#")
        ]

    def test_parameter(
        self,
        target,
        parameter,
        value="nova",
    ):
        data = {
            parameter: value
        }

        response = self.requester.post(
            target,
            data=data,
        )

        if response.error:
            return None

        return self.engine.analyze(
            response=response,
            value=parameter,
            finding_type="post_parameter",
        )

    def scan(
        self,
        target,
        value="nova",
    ):
        findings = []

        for parameter in self.wordlist:

            result = self.test_parameter(
                target,
                parameter,
                value,
            )

            if result is not None:
                findings.append(result)

        return findings