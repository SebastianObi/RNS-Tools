##############################################################################################################
# Include


#### System ####
import os
import subprocess

#### Reticulum ####
# Install: pip3 install rns
# Source: https://markqvist.github.io
import RNS


##############################################################################################################
# HandlerFiles Class


class HandlerFiles:
    def __init__(self, owner, path="files", root="", ext_allow=[], ext_deny=[], allow_all=True, allow=[], deny=[]):
        self.owner = owner
        self.path = path
        self.root = root
        self.ext_allow = ext_allow
        self.ext_deny = ext_deny
        self.ext_deny.append("allowed")
        self.allow_all = allow_all
        self.allow = allow
        self.deny = deny

        self.files = []

        if not os.path.isdir(self.path):
            os.makedirs(self.path)
            RNS.log("Server - HandlerFiles: Path was created", RNS.LOG_NOTICE)
        RNS.log("Server - HandlerFiles: Path: " + self.path, RNS.LOG_INFO)

        if "limiter_enabled" in self.owner.config["handler_files"] and  self.owner.config["handler_files"].getboolean("limiter_enabled"):
            self.limiter = RateLimiter(int(self.owner.config["handler_files"]["limiter_calls"]), int(self.owner.config["handler_files"]["limiter_size"]), int(self.owner.config["handler_files"]["limiter_duration"]))
        else:
            self.limiter = None


    def register(self):
        array = self.files.copy()

        self.files = []
        self.scan(self.path)
        self.files.sort()

        for file in array:
            if file not in self.files:
                self.owner.deregister_request_handler(file)

        for file in self.files:
            if file not in array:
                self.owner.register_request_handler(
                    path=self.root+file,
                    response_generator=self.response_handler,
                    limiter=self.limiter,
                    limiter_type=self.owner.LIMITER_TYPE_NONE
                )


    def scan(self, base_path):
        files = [file for file in os.listdir(base_path) if os.path.isfile(os.path.join(base_path, file)) and file[:1] != "."]
        directories = [file for file in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, file)) and file[:1] != "."]

        for file in files:
            ext = os.path.splitext(file)[1][1:]
            if ext in self.ext_allow or ext not in self.ext_deny:
                file = base_path+"/"+file
                self.files.append(file.replace(self.path, "").lstrip('/'))

        for directory in directories:
            self.scan(base_path+"/"+directory)


    def response_handler(self, path, data, request_id, link_id, remote_identity, requested_at):
        if request_id:
            RNS.log("Server - HandlerFiles: Request "+RNS.prettyhexrep(request_id)+" for: "+str(path), RNS.LOG_VERBOSE)
        else:
            RNS.log("Server - HandlerFiles: Request <local> for: "+str(path), RNS.LOG_VERBOSE)

        dest = RNS.Destination.hash_from_name_and_identity(self.owner.aspect_filter_conv, remote_identity)

        if data:
            RNS.log("Server - HandlerFiles: Data: "+str(data), RNS.LOG_DEBUG)

        if self.root:
            path = path.replace(self.root, "", 1)
        file_path = self.path+"/"+path

        allowed_path = file_path+".allowed"
        allowed = False

        if os.path.isfile(allowed_path):
            allowed_list = []

            try:
                if os.access(allowed_path, os.X_OK):
                    allowed_result = subprocess.run([allowed_path], stdout=subprocess.PIPE)
                    allowed_input = allowed_result.stdout
                else:
                    fh = open(allowed_path, "rb")
                    allowed_input = fh.read()
                    fh.close()

                allowed_hash_strs = allowed_input.splitlines()

                for hash_str in allowed_hash_strs:
                    if len(hash_str) == RNS.Identity.TRUNCATED_HASHLENGTH//8*2:
                        try:
                            allowed_hash = bytes.fromhex(hash_str.decode("utf-8"))
                            allowed_list.append(allowed_hash)
                        except Exception as e:
                            RNS.log("Server - HandlerFiles: Could not decode RNS Identity hash from: "+str(hash_str), RNS.LOG_DEBUG)
                            RNS.log("Server - HandlerFiles: The contained exception was: "+str(e), RNS.LOG_DEBUG)

            except Exception as e:
                RNS.log("Server - HandlerFiles: Error while fetching list of allowed identities for request: "+str(e), RNS.LOG_ERROR)

            if hasattr(remote_identity, "hash"):
                if self.owner.destination_mode == False and remote_identity.hash in allowed_list:
                    allowed = True
                elif self.owner.destination_mode == True and dest in allowed_list:
                    allowed = True

        elif self.allow_all:
            allowed = True

        elif hasattr(remote_identity, "hash"):
            if self.owner.destination_mode == False and remote_identity.hash in self.allow:
                allowed = True
            elif self.owner.destination_mode == True and dest in self.allow:
                allowed = True

        if hasattr(remote_identity, "hash"):
            if self.owner.destination_mode == False and remote_identity.hash in self.deny:
                allowed = False
            elif self.owner.destination_mode == True and dest in self.deny:
                allowed = False

        if request_id == None:
            allowed = True

        try:
            if allowed:
                RNS.log("Server - HandlerFiles: Serving "+file_path, RNS.LOG_VERBOSE)
                if os.access(file_path, os.X_OK):
                    env_map = {}
                    if "PATH" in os.environ:
                        env_map["PATH"] = os.environ["PATH"]
                    if link_id != None:
                        env_map["link_id"] = RNS.hexrep(link_id, delimit=False)
                    if remote_identity != None:
                        env_map["remote_identity"] = RNS.hexrep(remote_identity.hash, delimit=False)
                    if dest != None:
                        env_map["dest"] = RNS.hexrep(dest, delimit=False)

                    if data != None and isinstance(data, dict):
                        for e in data:
                            if isinstance(e, str) and (e.startswith("field_") or e.startswith("var_")):
                                env_map[e] = data[e]

                    generated = subprocess.run([file_path], stdout=subprocess.PIPE, env=env_map)
                    generated = generated.stdout
                    return generated
                else:
                    fh = open(file_path, "rb")
                    response_data = fh.read()
                    fh.close()
                    return response_data
            else:
                RNS.log("Server - HandlerFiles: Request denied", RNS.LOG_VERBOSE)
                return None

        except Exception as e:
            RNS.log("Server - HandlerFiles: Error occurred while handling request for: "+str(path), RNS.LOG_ERROR)
            RNS.log("Server - HandlerFiles: The contained exception was: "+str(e), RNS.LOG_ERROR)
            return None
