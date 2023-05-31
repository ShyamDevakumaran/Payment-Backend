from rest_framework.views import exception_handler


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)
    error = []
    if response is not None:
        if (response.status_code == 401):
            for err in response.data:
                if ("Invalid" in response.data['detail']):
                    response.data.update({"detail": "Your Login Expired"})
                error.append(str(response.data['detail']))
        else:
            for err in response.data:
                if (err != 'detail'):
                    if (err == 'non_field_errors'):
                        for each in response.data[err]:
                            error.append(each)
                    else:
                        error.append(
                            response.data[err][0].capitalize())
                else:
                    error.append(response.data[err])
        response.data['error_detail'] = error
        if (response.status_code == 401):
            del response.data['detail']
    return response
