import socket
from urllib.parse import urlsplit


class SubdomainDiscovery:

    def __init__(
        self,
        wordlist,
        timeout=3,
    ):
        self.wordlist = [
            word.strip().lower()
            for word in wordlist
            if word.strip()
            and not word.startswith("#")
        ]

        self.timeout = timeout

    def _base_domain(self, target: str) -> str:

        parsed = urlsplit(target)

        hostname = parsed.hostname

        if not hostname:
            raise ValueError(
                "Invalid target hostname"
            )

        return hostname

    def _resolve(self, hostname: str):

        try:
            addresses = socket.gethostbyname_ex(
                hostname
            )[2]

            return addresses

        except socket.gaierror:
            return []

    def scan(self, target: str):

        domain = self._base_domain(
            target
        )

        findings = []

        for prefix in self.wordlist:

            hostname = (
                f"{prefix}.{domain}"
            )

            addresses = self._resolve(
                hostname
            )

            if not addresses:
                continue

            findings.append({
                "type": "subdomain",
                "value": prefix,
                "hostname": hostname,
                "addresses": addresses,
            })

        return findings