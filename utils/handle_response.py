import json

def handle_response(msg: str, code: int):
  return {
    "body": json.dumps({ "message": msg }),
    "code": code
  }


class NotAuthorized:
  def __init__(self, message):
    self.message = message
    self.code = 401