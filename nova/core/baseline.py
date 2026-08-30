
from .response import ResponseData


class Baseline:

    def __init__(
        self,
        requester,
        target,
    ):
        self.requester = requester
        self.target = target

        self.response = None

    # --------------------------------------------------
    # Calibration
    # --------------------------------------------------

    def calibrate(self):

        try:
            self.response = (
                self.requester.get(
                    self.target
                )
            )

        except Exception as exc:
            self.response = ResponseData(
                url=self.target,
                status=0,
                body="",
                error=str(exc),
            )

        return self.response

    # --------------------------------------------------
    # Status
    # --------------------------------------------------

    @property
    def status(self):

        if not self.response:
            return None

        return self.response.status

    # --------------------------------------------------
    # Content length
    # --------------------------------------------------

    @property
    def length(self):

        if not self.response:
            return None

        return self.response.content_length

    # --------------------------------------------------
    # Body
    # --------------------------------------------------

    @property
    def body(self):

        if not self.response:
            return ""

        return self.response.body

    # --------------------------------------------------
    # Error
    # --------------------------------------------------

    @property
    def error(self):

        if not self.response:
            return None

        return self.response.error

    # --------------------------------------------------
    # Ready
    # --------------------------------------------------

    @property
    def ready(self):

        return (
            self.response is not None
            and not self.response.error
            and self.response.status != 0
        )

    # --------------------------------------------------
    # Response
    # --------------------------------------------------

    def get_response(self):

        return self.response

    # --------------------------------------------------
    # Reset
    # --------------------------------------------------

    def reset(self):

        self.response = None

