##############################################################################################################
# Include

import os, sys, subprocess, bcrypt, json, time, threading, enum, random, string, hashlib, base64
from collections import defaultdict


##############################################################################################################
# Install


def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])


def install_check(package):
    try:
        __import__(package)
    except ImportError:
        install(package)


def install_requirements():
    path = os.getcwd() + "/requirements.txt"
    with open(path, encoding="utf-8") as f:
        packages = f.read().splitlines()

    for package in packages:
        if "==" in package:
            package_name = package.split("==")[0]
        elif ">=" in package:
            package_name = package.split(">=")[0]
        elif ">" in package:
            package_name = package.split(">")[0]
        elif "<=" in package:
            package_name = package.split("<=")[0]
        elif "<" in package:
            package_name = package.split("<")[0]
        else:
            package_name = package

        install_check(package_name)


##############################################################################################################
# Invitation


def invitation_code_generate():
    charset = string.digits + string.ascii_uppercase
    code = "".join(random.choices(charset, k=7))

    return code+invitation_code_checksum(code)


def invitation_code_checksum(code):
    hash_object = hashlib.sha256(code.encode("utf-8"))
    hash_bytes = hash_object.digest()

    hash_base64 = base64.urlsafe_b64encode(hash_bytes).decode("utf-8").strip("=")

    charset = string.digits + string.ascii_uppercase
    clean_base64 = "".join(c for c in hash_base64 if c in charset)

    checksum_value = int(clean_base64[:2], 36)
    checksum_char = charset[checksum_value % 36]

    return checksum_char


def invitation_code_verify(code):
    if len(code) != 8:
        return False

    if not all(c in string.digits + string.ascii_uppercase for c in code[:7]):
        return False

    code_part = code[:7]
    checksum_part = code[7]

    return invitation_code_checksum(code_part) == checksum_part


##############################################################################################################
# JSON Class


class json_encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, enum.Enum):
            return obj.name
        return json.JSONEncoder.default(self, obj)


##############################################################################################################
# Password


def password_hash_get(password:str):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def password_hash_check(password:str, hash:str):
    return bcrypt.checkpw(password.encode("utf-8"), hash.encode("utf-8"))


##############################################################################################################
# RateLimiter Class


class RateLimiter:
    def __init__(self, calls, size, duration):
        self.calls = calls
        self.size = size
        self.duration = duration
        self.ts = time.time()
        self.data_calls = {}
        self.data_size = {}
        self.lock = threading.Lock()
        threading.Thread(target=self._jobs, daemon=True).start()


    def handle(self, id):
        if self.handle_call(id) and self.handle_size(id, 0):
            return True
        else:
            return False


    def handle_call(self, id):
        with self.lock:
            if self.calls == 0:
                return True
            if id not in self.data_calls:
                self.data_calls[id] = []
            self.data_calls[id] = [t for t in self.data_calls[id] if t > self.ts - self.duration]
            if len(self.data_calls[id]) >= self.calls:
                return False
            else:
                self.data_calls[id].append(self.ts)
                return True


    def handle_size(self, id, size):
        with self.lock:
            if self.size == 0:
                return True
            if id not in self.data_size:
                self.data_size[id] = [0, self.ts]
            if self.data_size[id][1] <= self.ts - self.duration:
                self.data_size[id] = [0, self.ts]
            if self.data_size[id][0] >= self.size:
                return False
            else:
                self.data_size[id][0] += size
                self.data_size[id][1] = self.ts
                return True


    def _jobs(self):
        while True:
            time.sleep(self.duration)
            self.ts = time.time()
            with self.lock:
                if self.calls > 0:
                    for id in list(self.data_calls.keys()):
                        self.data_calls[id] = [t for t in self.data_calls[id] if t > self.ts - self.duration]
                        if not self.data_calls[id]:
                            del self.data_calls[id]

                if self.size > 0:
                    for id in list(self.data_size.keys()):
                        if self.data_size[id][1] <= self.ts - self.duration:
                            del self.data_size[id]


##############################################################################################################
# ResponseError Class


class ResponseError(Exception):
    def __init__(self, error_number, error_reason, error_key, error_message):
        super().__init__(f"{error_key} - {error_message}")
        self.error_number = error_number
        self.error_reason = error_reason
        self.error_key = error_key
        self.error_message = error_message

    def __str__(self):
        return f"{self.args[0]}"


##############################################################################################################
# Response


def response_create(code, status, message, data=None):
    response = {
        "status": status,
        "code": code,
        "message": message
    }
    if data:
        response["data"] = data
    return json.dumps(response, cls=json_encoder)


RESPONSE_CODES = {
    "200":  "RESULT_OK",
    "201":  "RESULT_CREATED",
    "204":  "RESULT_NO_CONTENT",
    "400":  "ERROR_BAD_REQUEST",
    "401":  "ERROR_UNAUTHORIZED",
    "403":  "ERROR_FORBIDDEN",
    "404":  "ERROR_NOT_FOUND",
    "409":  "ERROR_CONFLICT",
    "429":  "TOO_MANY_REQUESTS",
    "500":  "ERROR_INTERNAL",
    "503":  "ERROR_SERVICE_UNAVAILABLE",
    "0x00": "ERROR_INVALID_IDENTITY",
    "0x01": "ERROR_INVALID_DATA",
    "0x02": "ERROR_INVALID_PARAMETERS",
    "0x03": "ERROR_MEMBER_NOT_FOUND",
    "0x04": "ERROR_DEVICE_NOT_FOUND",
    "0x05": "ERROR_INVITE_CODE_INVALID",
    "0x06": "ERROR_INVITE_CODE_USED"
}
