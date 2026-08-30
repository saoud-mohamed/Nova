import time


class AdaptiveController:

    def __init__(
        self,
        initial_delay: float = 0.0,
        max_delay: float = 5.0,
        backoff_factor: float = 2.0,
        recovery_factor: float = 0.9,
    ):
        self.delay = max(0.0, initial_delay)

        self.max_delay = max(
            self.delay,
            max_delay,
        )

        self.backoff_factor = max(
            1.0,
            backoff_factor,
        )

        self.recovery_factor = min(
            max(recovery_factor, 0.0),
            1.0,
        )

    def observe(self, status: int):
        """
        Adapt request delay according to server response.

        429/503/504:
            Increase delay using exponential backoff.

        2xx/3xx:
            Slowly reduce the delay.
        """

        if status in {429, 503, 504}:

            if self.delay <= 0:
                self.delay = 0.1
            else:
                self.delay = min(
                    self.delay * self.backoff_factor,
                    self.max_delay,
                )

        elif 200 <= status < 400:

            self.delay = max(
                0.0,
                self.delay * self.recovery_factor,
            )

    def wait(self):
        """Wait according to the current adaptive delay."""

        if self.delay > 0:
            time.sleep(self.delay)

    def reset(self):
        """Reset adaptive delay."""

        self.delay = 0.0