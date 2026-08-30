import time

import requests

from .response import ResponseData
from .rate_limiter import RateLimiter
from .adaptive import AdaptiveController


class Requester:

    def __init__(
        self,
        timeout: int = 10,
        rate: float = 0,
        user_agent: str = "Nova/6.6"
    ):

        self.timeout = timeout

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": user_agent
        })

        self.rate_limiter = RateLimiter(
            rate
        )

        self.adaptive = (
            AdaptiveController()
        )

    def _request(
        self,
        method: str,
        url: str,
        **kwargs
    ):

        self.rate_limiter.wait()

        self.adaptive.wait()

        start = time.perf_counter()

        try:

            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                allow_redirects=False,
                **kwargs
            )

            elapsed = (
                time.perf_counter()
                - start
            ) * 1000

            body = response.text

            result = ResponseData(
                url=url,
                status=response.status_code,
                body=body,
                headers=dict(
                    response.headers
                ),
                elapsed_ms=round(
                    elapsed,
                    2
                ),
                content_length=len(
                    response.content
                ),
                words=len(
                    body.split()
                ),
                lines=len(
                    body.splitlines()
                )
            )

            self.adaptive.observe(
                response.status_code
            )

            return result

        except requests.RequestException as exc:

            return ResponseData(
                url=url,
                status=0,
                body="",
                headers={},
                elapsed_ms=0,
                content_length=0,
                words=0,
                lines=0,
                error=str(exc)
            )

    def get(self, url, **kwargs):

        return self._request(
            "GET",
            url,
            **kwargs
        )

    def post(
        self,
        url,
        data=None,
        json=None,
        **kwargs
    ):

        return self._request(
            "POST",
            url,
            data=data,
            json=json,
            **kwargs
        )

    def put(
        self,
        url,
        data=None,
        json=None,
        **kwargs
    ):

        return self._request(
            "PUT",
            url,
            data=data,
            json=json,
            **kwargs
        )

    def delete(
        self,
        url,
        **kwargs
    ):

        return self._request(
            "DELETE",
            url,
            **kwargs
        )