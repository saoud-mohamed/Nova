import threading
import time


class RateLimiter:

    def __init__(self, rate: float = 0):

        self.rate = rate

        self.lock = threading.Lock()

        self.next_request = 0.0

    def wait(self):

        if self.rate <= 0:
            return

        interval = 1.0 / self.rate

        with self.lock:

            now = time.monotonic()

            if now < self.next_request:

                time.sleep(
                    self.next_request - now
                )

            self.next_request = (
                max(
                    now,
                    self.next_request
                )
                + interval
            )