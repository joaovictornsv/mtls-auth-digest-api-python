import logging
import json
import azure.functions as func
from ..lib.middlewares.auth_digest import AuthDigest
from ..lib.middlewares.certificate import CertificateValidator
from ..lib.utils.handle_response import handle_response

auth_digest = AuthDigest()
certificate_validator = CertificateValidator()


def main(req: func.HttpRequest) -> func.HttpResponse:

    try:
        certificate_validator.execute(req.headers)
        auth_digest.execute(req.headers)

        response = handle_response("Success", 200)
        return func.HttpResponse(response["body"], status_code=response["code"])

    except Exception as error:
        code = 500
        if error.args[1] and isinstance(error.args[1], int):
            code = error.args[1]
        return func.HttpResponse(str(error.args[0]), status_code=code)
