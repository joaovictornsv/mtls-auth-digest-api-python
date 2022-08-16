import logging
import json
import azure.functions as func
from ..middlewares.auth_digest import AuthDigest
from ..middlewares.certificate import CertificateValidator
from ..utils.handle_response import handle_response
auth_digest = AuthDigest()
certificate_validator = CertificateValidator()

def main(req: func.HttpRequest) -> func.HttpResponse:

    try:
        certificate_validator.execute(req.headers)
        auth_digest.execute(req.headers)

        response = handle_response("Success", 200)
        return func.HttpResponse(response["body"], status_code=response["code"])
    
    except Exception as e:
        code = 500
        if e.args[1] and type(e.args[1]) == int:
            code = e.args[1]
        return func.HttpResponse(str(e.args[0]), status_code=code)