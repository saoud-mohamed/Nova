import re


class FormExtractor:

    FORM_RE = re.compile(
        r"<form\b([^>]*)>(.*?)</form>",
        re.IGNORECASE | re.DOTALL,
    )

    INPUT_RE = re.compile(
        r"<input\b([^>]*)>",
        re.IGNORECASE,
    )

    NAME_RE = re.compile(
        r'\bname\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )

    ACTION_RE = re.compile(
        r'\baction\s*=\s*["\']([^"\']*)["\']',
        re.IGNORECASE,
    )

    METHOD_RE = re.compile(
        r'\bmethod\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )

    def extract(self, html: str):

        forms = []

        for attributes, content in self.FORM_RE.findall(
            html or ""
        ):

            action_match = self.ACTION_RE.search(
                attributes
            )

            method_match = self.METHOD_RE.search(
                attributes
            )

            action = (
                action_match.group(1)
                if action_match
                else ""
            )

            method = (
                method_match.group(1).upper()
                if method_match
                else "GET"
            )

            inputs = []

            for input_attributes in self.INPUT_RE.findall(
                content
            ):

                name_match = self.NAME_RE.search(
                    input_attributes
                )

                if not name_match:
                    continue

                inputs.append(
                    name_match.group(1)
                )

            forms.append({
                "action": action,
                "method": method,
                "parameters": inputs,
            })

        return forms