def flatten_json(
    data,
    prefix="",
):
    result = {}

    if isinstance(data, dict):

        for key, value in data.items():

            path = (
                f"{prefix}.{key}"
                if prefix
                else key
            )

            result.update(
                flatten_json(
                    value,
                    path,
                )
            )

    elif isinstance(data, list):

        for index, value in enumerate(data):

            path = (
                f"{prefix}[{index}]"
            )

            result.update(
                flatten_json(
                    value,
                    path,
                )
            )

    else:

        result[prefix] = data

    return result