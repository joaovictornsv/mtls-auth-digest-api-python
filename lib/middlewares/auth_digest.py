import re
import os
from hashlib import sha256

AUTH_DIGEST_GLOBAL_KEY = os.environ.get("AUTH_DIGEST_GLOBAL_KEY")

AUTH_DIGEST_MOBILE_API_USER_KEY = os.environ.get("AUTH_DIGEST_MOBILE_API_USER_KEY")
AUTH_DIGEST_MOBILE_API_STATIC_KEY = os.environ.get("AUTH_DIGEST_MOBILE_API_STATIC_KEY")

STATIC_KEYS = {}
STATIC_KEYS[AUTH_DIGEST_MOBILE_API_USER_KEY] = AUTH_DIGEST_MOBILE_API_STATIC_KEY


class AuthDigest:
    def execute(self, headers: dict):
        digest = self.__extract_digest_header(headers)

        parsed = self.__parse_authentication_info(digest)
        user = parsed["user"]
        key = parsed["key"]
        random_number = parsed["iv"]

        api_static_key = self.__get_static_key(user)
        api_key = self.__generate_hash(user, api_static_key, random_number)

        if key != api_key:
            raise Exception("Invalid API Key", 401)

    def __validate_digest_string(self, value: str):
        match = re.search(
            "^Digest ((user|key|iv)=[a-zA-Z0-9-_]*, )*(user|key|iv)=[a-zA-Z0-9-_]*$",
            value,
        )
        if not match:
            raise Exception("Provide a valid digest", 401)

    def __extract_digest_header(self, headers: dict):
        digest = headers.get("www-authenticate")
        if not digest:
            raise Exception("Provide digest authentication", 401)

        self.__validate_digest_string(digest)
        return digest

    def __parse_authentication_info(self, auth_data: str):
        auth_obj = {}

        fields = auth_data.replace("Digest ", "").split(", ")
        for field in fields:
            key, value = field.split("=")
            auth_obj[key] = value

        return auth_obj

    def __get_static_key(self, value: str):
        if value not in STATIC_KEYS:
            raise Exception("API User Key Unauthorized", 401)

        return STATIC_KEYS[value]

    def __generate_hash(self, user: str, static_api_key: str, random_number: str):
        hash_api = sha256(
            f"{user}:{static_api_key}:{random_number}:{AUTH_DIGEST_GLOBAL_KEY}".encode(
                "utf-8"
            )
        )
        hash_digest = hash_api.hexdigest()
        return hash_digest
