##############################################################################################################
# Include


#### System ####
import os
import time
import random
import threading

#### Reticulum ####
# Install: pip3 install rns
# Source: https://markqvist.github.io
import RNS
import RNS.vendor.umsgpack as msgpack

#### Internal ####
from utils.utils import RateLimiter, ResponseError, response_create, RESPONSE_CODES as resp
from db.connection import db_session
from db.schema import logs


##############################################################################################################
# ServerProvisioning Class


class ServerProvisioning:
    ACCOUNT_INVITE_STATE_NONE          = 0x00
    ACCOUNT_INVITE_STATE_SUCCESSFULL   = 0x01
    ACCOUNT_INVITE_STATE_ERROR_INVALID = 0x02
    ACCOUNT_INVITE_STATE_ERROR_USED    = 0x03

    BLOCKCHAIN_TOKEN_DID     = 0x01
    BLOCKCHAIN_TOKEN_PRIMARY = 0x02

    CONNECTION_TIMEOUT = 10 # Seconds

    JOBS_PERIODIC_DELAY    = 10 # Seconds
    JOBS_PERIODIC_INTERVAL = 60 # Seconds

    KEY_RESULT        = 0x0A # Result
    KEY_RESULT_REASON = 0x0B # Result - Reason
    KEY_A             = 0x0C # Account
    KEY_D             = 0x0D # Directory
    KEY_I             = 0x0E # Invitation
    KEY_S             = 0x0F # Service
    KEY_T             = 0x10 # Transaction
    KEY_TA            = 0x11 # Task

    KEY_A_DATA = 0x00
    KEY_A_TS   = 0x01

    KEY_A_MAPPING = {
        "data": KEY_A_DATA,
        "ts":   KEY_A_TS,
    }

    KEY_D_CMD                    = 0x00
    KEY_D_CMD_ENTRY              = 0x01
    KEY_D_CMD_RESULT             = 0x02
    KEY_D_ENTRYS                 = 0x03
    KEY_D_FILTER                 = 0x04
    KEY_D_GROUP                  = 0x05
    KEY_D_LIMIT                  = 0x06
    KEY_D_LIMIT_START            = 0x07
    KEY_D_ORDER                  = 0x08
    KEY_D_RX_ENTRYS              = 0x09
    KEY_D_RX_ENTRYS_COUNT        = 0x0A
    KEY_D_RX_GROUP_ENTRYS        = 0x0B
    KEY_D_RX_GROUP_ENTRYS_COUNT  = 0x0C
    KEY_D_SEARCH                 = 0x0D

    KEY_D_MAPPING = {
    }

    KEY_D_ENTRYS_AUTH_ROLE      = 0x00
    KEY_D_ENTRYS_CITY           = 0x01
    KEY_D_ENTRYS_COUNT          = 0x02
    KEY_D_ENTRYS_COUNTRY        = 0x03
    KEY_D_ENTRYS_DATA           = 0x04
    KEY_D_ENTRYS_DEST           = 0x05
    KEY_D_ENTRYS_DISPLAY_NAME   = 0x06
    KEY_D_ENTRYS_HOP_COUNT      = 0x07
    KEY_D_ENTRYS_LOCATION_LAT   = 0x08
    KEY_D_ENTRYS_LOCATION_LON   = 0x09
    KEY_D_ENTRYS_OCCUPATION     = 0x0A
    KEY_D_ENTRYS_OWNER          = 0x0B
    KEY_D_ENTRYS_SHOP_GOODS     = 0x0C
    KEY_D_ENTRYS_SHOP_SERVICES  = 0x0D
    KEY_D_ENTRYS_SKILLS         = 0x0E
    KEY_D_ENTRYS_STATE          = 0x0F
    KEY_D_ENTRYS_STATE_TS       = 0x10
    KEY_D_ENTRYS_TS             = 0x11
    KEY_D_ENTRYS_TS_ADD         = 0x12
    KEY_D_ENTRYS_TS_EDIT        = 0x13
    KEY_D_ENTRYS_TYPE           = 0x14

    KEY_D_ENTRYS_MAPPING = {
        "auth_role":     KEY_D_ENTRYS_AUTH_ROLE,
        "city":          KEY_D_ENTRYS_CITY,
        "count":         KEY_D_ENTRYS_COUNT,
        "country":       KEY_D_ENTRYS_COUNTRY,
        "data":          KEY_D_ENTRYS_DATA,
        "dest":          KEY_D_ENTRYS_DEST,
        "display_name":  KEY_D_ENTRYS_DISPLAY_NAME,
        "hop_count":     KEY_D_ENTRYS_HOP_COUNT,
        "location_lat":  KEY_D_ENTRYS_LOCATION_LAT,
        "location_lon":  KEY_D_ENTRYS_LOCATION_LON,
        "occupation":    KEY_D_ENTRYS_OCCUPATION,
        "owner":         KEY_D_ENTRYS_OWNER,
        "shop_goods":    KEY_D_ENTRYS_SHOP_GOODS,
        "shop_services": KEY_D_ENTRYS_SHOP_SERVICES,
        "skills":        KEY_D_ENTRYS_SKILLS,
        "state":         KEY_D_ENTRYS_STATE,
        "state_ts":      KEY_D_ENTRYS_STATE_TS,
        "ts":            KEY_D_ENTRYS_TS,
        "ts_add":        KEY_D_ENTRYS_TS_ADD,
        "ts_edit":       KEY_D_ENTRYS_TS_EDIT,
        "type":          KEY_D_ENTRYS_TYPE,
    }

    KEY_I_DATA = 0x00
    KEY_I_TS   = 0x01

    KEY_I_MAPPING = {
        "data": KEY_I_DATA,
        "ts":   KEY_I_TS,
    }

    KEY_S_DATA = 0x00
    KEY_S_TS   = 0x01

    KEY_S_MAPPING = {
        "data": KEY_S_DATA,
        "ts":   KEY_S_TS,
    }

    KEY_T_DATA         = 0x00
    KEY_T_ID           = 0x01
    KEY_T_INDEX        = 0x02
    KEY_T_STATE        = 0x03
    KEY_T_STATE_REASON = 0x04
    KEY_T_TS           = 0x05
    KEY_T_TYPE         = 0x06

    KEY_T_MAPPING = {
        "data":         KEY_T_DATA,
        "id":           KEY_T_ID,
        "index":        KEY_T_INDEX,
        "state":        KEY_T_STATE,
        "state_reason": KEY_T_STATE_REASON,
        "ts":           KEY_T_TS,
        "type":         KEY_T_TYPE,
    }

    KEY_TA_DATA = 0x00
    KEY_TA_TS   = 0x01

    KEY_TA_MAPPING = {
        "data": KEY_TA_DATA,
        "ts":   KEY_TA_TS,
    }

    LIMITER_TYPE_JSON    = 0x00
    LIMITER_TYPE_MSGPACK = 0x01
    LIMITER_TYPE_NONE    = 0x02

    RESULT_ERROR       = 0x00
    RESULT_OK          = 0x01
    RESULT_SYNCRONIZE  = 0x02
    RESULT_NO_IDENTITY = 0x03
    RESULT_NO_USER     = 0x04
    RESULT_NO_RIGHT    = 0x05
    RESULT_NO_DATA     = 0x06
    RESULT_LIMIT_ALL   = 0x07
    RESULT_LIMIT_PEER  = 0x08
    RESULT_PARTIAL     = 0x09
    RESULT_DISABLED    = 0xFE
    RESULT_BLOCKED     = 0xFF

    SERVICE_STATE_FAILED      = 0x00 # Failed
    SERVICE_STATE_SUCCESSFULL = 0x01 # Successfull
    SERVICE_STATE_WAITING     = 0x02 # Waiting in local cache
    SERVICE_STATE_SYNCING     = 0x03 # Syncing/Transfering to server
    SERVICE_STATE_PROCESSING  = 0x04 # Processing/Execution on the server
    SERVICE_STATE_FAILED_TMP  = 0x05 # Temporary failed

    STATE_NO_PATH            = 0x00
    STATE_PATH_REQUESTED     = 0x01
    STATE_ESTABLISHING_LINK  = 0x02
    STATE_LINK_TIMEOUT       = 0x03
    STATE_LINK_ESTABLISHED   = 0x04
    STATE_REQUESTING         = 0x05
    STATE_REQUEST_SENT       = 0x06
    STATE_REQUEST_FAILED     = 0x07
    STATE_REQUEST_TIMEOUT    = 0x08
    STATE_RECEIVING_RESPONSE = 0x09
    STATE_TRANSFERRING       = 0x0A
    STATE_DISCONECTED        = 0xFD
    STATE_DONE               = 0xFF

    TRANSACTION_STATE_FAILED      = 0x00 # Failed
    TRANSACTION_STATE_SUCCESSFULL = 0x01 # Successfull
    TRANSACTION_STATE_WAITING     = 0x02 # Waiting in local cache
    TRANSACTION_STATE_SYNCING     = 0x03 # Syncing/Transfering to server
    TRANSACTION_STATE_PROCESSING  = 0x04 # Processing/Execution on the server
    TRANSACTION_STATE_FAILED_TMP  = 0x05 # Temporary failed

    TRANSACTION_STATE_REASON_None               = 0x00
    TRANSACTION_STATE_REASON_Disabled           = 0x01
    TRANSACTION_STATE_REASON_NoRight            = 0x02
    TRANSACTION_STATE_REASON_LimitAll           = 0x03
    TRANSACTION_STATE_REASON_LimitPeer          = 0x04
    TRANSACTION_STATE_REASON_InvalidData        = 0x05
    TRANSACTION_STATE_REASON_InvalidParameters  = 0x06
    TRANSACTION_STATE_REASON_Conflict           = 0x07
    TRANSACTION_STATE_REASON_Internal           = 0x08
    TRANSACTION_STATE_REASON_ServiceUnavailable = 0x09
    TRANSACTION_STATE_REASON_EntryFound         = 0x0A
    TRANSACTION_STATE_REASON_EntryNotFound      = 0x0B
    TRANSACTION_STATE_REASON_MemberFound        = 0x0C
    TRANSACTION_STATE_REASON_MemberNotFound     = 0x0D
    TRANSACTION_STATE_REASON_DeviceFound        = 0x0E
    TRANSACTION_STATE_REASON_DeviceNotFound     = 0x0F
    TRANSACTION_STATE_REASON_TaskFound          = 0x10
    TRANSACTION_STATE_REASON_TaskNotFound       = 0x11

    TRANSACTION_TYPE_ACCOUNT_CREATE    = 0x00
    TRANSACTION_TYPE_ACCOUNT_EDIT      = 0x01
    TRANSACTION_TYPE_ACCOUNT_PROVE     = 0x02
    TRANSACTION_TYPE_ACCOUNT_RESTORE   = 0x03
    TRANSACTION_TYPE_ACCOUNT_DELETE    = 0x04
    TRANSACTION_TYPE_INVITATION_CREATE = 0x05
    TRANSACTION_TYPE_INVITATION_EDIT   = 0x06
    TRANSACTION_TYPE_INVITATION_DELETE = 0x07
    TRANSACTION_TYPE_SERVICE_CREATE    = 0x08
    TRANSACTION_TYPE_SERVICE_EDIT      = 0x09
    TRANSACTION_TYPE_SERVICE_DELETE    = 0x0A

    TYPE_DIRECTORY_ANNOUNCE = 0x00
    TYPE_DIRECTORY_MEMBER   = 0x01
    TYPE_DIRECTORY_SERVICE  = 0x02
    TYPE_SYNC               = 0x03
    TYPE_UNKNOWN            = 0xFF


    def __init__(self, storage_path=None, identity_file="identity", identity=None, ratchets=False,
        destination_name="nomadnetwork", destination_type="provisioning", destination_conv_name="lxmf", destination_conv_type="delivery", destination_mode=True,
        announce_startup=False, announce_startup_delay=0, announce_periodic=False, announce_periodic_interval=360, announce_data="", announce_hidden=False,
        register_startup=True, register_startup_delay=0, register_periodic=True, register_periodic_interval=30,
        config=None, admins=[],
        limiter_server_enabled=False, limiter_server_calls=1000, limiter_server_size=0, limiter_server_duration=60,
        limiter_peer_enabled=True, limiter_peer_calls=30, limiter_peer_size=0, limiter_peer_duration=60,
    ):

        self.storage_path = storage_path

        self.identity_file = identity_file
        self.identity = identity
        self.ratchets = ratchets

        self.destination_name = destination_name
        self.destination_type = destination_type
        self.aspect_filter = self.destination_name + "." + self.destination_type
        self.destination_conv_name = destination_conv_name
        self.destination_conv_type = destination_conv_type
        self.aspect_filter_conv = self.destination_conv_name + "." + self.destination_conv_type
        self.destination_mode = destination_mode

        self.announce_startup = announce_startup
        self.announce_startup_delay = int(announce_startup_delay)
        if self.announce_startup_delay == 0:
            self.announce_startup_delay = random.randint(5, 30)

        self.announce_periodic = announce_periodic
        self.announce_periodic_interval = int(announce_periodic_interval)

        self.announce_data = announce_data
        self.announce_hidden = announce_hidden

        self.register_startup = register_startup
        self.register_startup_delay = int(register_startup_delay)

        self.register_periodic = register_periodic
        self.register_periodic_interval = int(register_periodic_interval)

        self.config = config

        self.admins = admins

        if self.storage_path:
            if not os.path.isdir(self.storage_path):
                os.makedirs(self.storage_path)
                RNS.log("Server - Storage path was created", RNS.LOG_NOTICE)
            RNS.log("Server - Storage path: " + self.storage_path, RNS.LOG_INFO)

        if self.identity:
            RNS.log("Server - Using existing Primary Identity %s" % (str(self.identity)))
        else:
            if not self.storage_path:
                RNS.log("Server - No storage_path parameter", RNS.LOG_ERROR)
                return
            if not self.identity_file:
                self.identity_file = "identity"
            self.identity_path = self.storage_path + "/" + self.identity_file
            if os.path.isfile(self.identity_path):
                try:
                    self.identity = RNS.Identity.from_file(self.identity_path)
                    if self.identity != None:
                        RNS.log("Server - Loaded Primary Identity %s from %s" % (str(self.identity), self.identity_path))
                    else:
                        RNS.log("Server - Could not load the Primary Identity from "+self.identity_path, RNS.LOG_ERROR)
                except Exception as e:
                    RNS.log("Server - Could not load the Primary Identity from "+self.identity_path, RNS.LOG_ERROR)
                    RNS.log("Server - The contained exception was: %s" % (str(e)), RNS.LOG_ERROR)
            else:
                try:
                    RNS.log("Server - No Primary Identity file found, creating new...")
                    self.identity = RNS.Identity()
                    self.identity.to_file(self.identity_path)
                    RNS.log("Server - Created new Primary Identity %s" % (str(self.identity)))
                except Exception as e:
                    RNS.log("Server - Could not create and save a new Primary Identity", RNS.LOG_ERROR)
                    RNS.log("Server - The contained exception was: %s" % (str(e)), RNS.LOG_ERROR)

        self.destination = RNS.Destination(self.identity, RNS.Destination.IN, RNS.Destination.SINGLE, self.destination_name, self.destination_type)

        if self.ratchets:
            self.destination.enable_ratchets(self.identity_path+"."+RNS.hexrep(self.destination.hash, delimit=False)+".ratchets")

        self.destination.set_proof_strategy(RNS.Destination.PROVE_ALL)

        self.destination.set_link_established_callback(self.peer_connected)

        self.db = db_session(host=self.config["database"]["host"], port=self.config["database"]["port"], user=self.config["database"]["user"], password=self.config["database"]["password"], database=self.config["database"]["database"])

        if limiter_server_enabled:
            self.limiter_server = RateLimiter(int(limiter_server_calls), int(limiter_server_size), int(limiter_server_duration))
        else:
            self.limiter_server = None

        if limiter_peer_enabled:
            self.limiter_peer = RateLimiter(int(limiter_peer_calls), int(limiter_peer_size), int(limiter_peer_duration))
        else:
            self.limiter_peer = None

        # HandlerAPI
        if self.config.has_section("handler_api") and self.config["handler_api"].getboolean("enabled"):
            from server.handler_api import HandlerAPI
            self.handler_api = HandlerAPI(self)

        # HandlerDirectory
        if self.config.has_section("handler_directory") and self.config["handler_directory"].getboolean("enabled"):
            from server.handler_directory import HandlerDirectory
            self.handler_directory = HandlerDirectory(self)

        # HandlerFiles
        if self.config.has_section("handler_files") and self.config["handler_files"].getboolean("enabled"):
            from server.handler_files import HandlerFiles
            self.handler_files = HandlerFiles(
                owner=self,
                path=self.storage_path+"/"+self.config["handler_files"]["path"] if not self.config["handler_files"]["path"].startswith("/") and self.storage_path else self.config["handler_files"]["path"],
                root=self.config["handler_files"]["root"],
                ext_allow=self.config["handler_files"]["ext_allow"].split(","),
                ext_deny=self.config["handler_files"]["ext_deny"].split(",")
            )

        # Handler IOP
        if self.config.has_section("handler_iop") and self.config["handler_iop"].getboolean("enabled"):
            from server.handler_iop import HandlerIOP
            self.handler_iop = HandlerIOP(self)

        # HandlerSync
        if self.config.has_section("handler_sync") and self.config["handler_sync"].getboolean("enabled"):
            from server.handler_sync import HandlerSync
            self.handler_sync = HandlerSync(self)


    def start(self):
        if self.announce_startup or self.announce_periodic:
            self.announce(initial=True)

        if self.register_startup or self.register_periodic:
            self.register(True)


    def stop(self):
        pass


    def register_announce_callback(self, handler_function):
        self.announce_callback = handler_function(self.aspect_filter)
        RNS.Transport.register_announce_handler(self.announce_callback)


    def destination_hash(self):
        return self.destination.hash


    def destination_hash_str(self):
        return RNS.hexrep(self.destination.hash, False)


    def destination_check(self, destination):
        if type(destination) is not bytes:
            if len(destination) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                destination = destination[1:-1]

            if len(destination) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                RNS.log("Server - Destination length is invalid", RNS.LOG_ERROR)
                return False

            try:
                destination = bytes.fromhex(destination)
            except Exception as e:
                RNS.log("Server - Destination is invalid", RNS.LOG_ERROR)
                return False

        return True


    def destination_correct(self, destination):
        if type(destination) is not bytes:
            if len(destination) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                destination = destination[1:-1]

            if len(destination) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                return ""

            try:
                destination_bytes = bytes.fromhex(destination)
                return destination
            except Exception as e:
                return ""

        return ""


    def announce(self, app_data=None, attached_interface=None, initial=False):
        announce_timer = None

        if self.announce_periodic and self.announce_periodic_interval > 0:
            announce_timer = threading.Timer(self.announce_periodic_interval*60, self.announce)
            announce_timer.daemon = True
            announce_timer.start()

        if initial:
            if self.announce_startup:
                if self.announce_startup_delay > 0:
                    if announce_timer is not None:
                        announce_timer.cancel()
                    announce_timer = threading.Timer(self.announce_startup_delay, self.announce)
                    announce_timer.daemon = True
                    announce_timer.start()
                else:
                    self.announce_now(app_data=app_data, attached_interface=attached_interface)
            return

        self.announce_now(app_data=app_data, attached_interface=attached_interface)


    def announce_now(self, app_data=None, attached_interface=None):
        if self.announce_hidden:
            self.destination.announce("".encode("utf-8"), attached_interface=attached_interface)
            RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()) +" (Hidden)", RNS.LOG_DEBUG)
        elif app_data != None:
            if isinstance(app_data, str):
                self.destination.announce(app_data.encode("utf-8"), attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()) +": " + app_data, RNS.LOG_DEBUG)
            else:
                self.destination.announce(app_data, attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()), RNS.LOG_DEBUG)
        else:
            if isinstance(self.announce_data, str):
                self.destination.announce(self.announce_data.encode("utf-8"), attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()) +": " + self.announce_data, RNS.LOG_DEBUG)
            else:
                self.destination.announce(self.announce_data, attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()), RNS.LOG_DEBUG)


    def register(self, initial=False):
        if self.register_periodic and self.register_periodic_interval > 0:
            register_timer = threading.Timer(self.register_periodic_interval*60, self.register)
            register_timer.daemon = True
            register_timer.start()

        if initial:
            if self.register_startup:
                if self.register_startup_delay > 0:
                    register_timer.cancel()
                    register_timer = threading.Timer(self.register_startup_delay, self.register)
                    register_timer.daemon = True
                    register_timer.start()
                else:
                    self.register_now(initial)
            return

        self.register_now(initial)


    def register_now(self, initial=False):
        RNS.log("Server - Register", RNS.LOG_DEBUG)

        if self.config.has_section("handler_files") and self.config["handler_files"].getboolean("enabled"):
            self.handler_files.register()


    def register_request_handler(self, path, response_generator=None, allow=None, allowed_list=None, limiter=None, limiter_type=None):
        self.destination.register_request_handler(
            path=path,
            response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: self.request_handler(response_generator, limiter, limiter_type, path, data, request_id, link_id, remote_identity, requested_at),
            allow=allow if allow != None else RNS.Destination.ALLOW_ALL,
            allowed_list=allowed_list
        )


    def deregister_request_handler(self, path):
        self.destination.deregister_request_handler(path)


    def request_handler(self, callback, limiter, limiter_type, path, data, request_id, link_id, remote_identity, requested_at):
        if not remote_identity:
            if limiter_type == self.LIMITER_TYPE_JSON:
                return response_create("0x00", resp.get("0x00"), "Invalid identity")
            elif limiter_type == self.LIMITER_TYPE_MSGPACK:
                return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_IDENTITY})
            else:
                return None

        if self.limiter_server and not self.limiter_server.handle("server"):
            if limiter_type == self.LIMITER_TYPE_JSON:
                return response_create("429", resp.get("429"), "Unusual activity detected")
            elif limiter_type == self.LIMITER_TYPE_MSGPACK:
                return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_SERVER})
            else:
                return None

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            if limiter_type == self.LIMITER_TYPE_JSON:
                return response_create("429", resp.get("429"), "Unusual activity detected")
            elif limiter_type == self.LIMITER_TYPE_MSGPACK:
                return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_PEER})
            else:
                return None

        if limiter and not limiter.handle(str(remote_identity)):
            if limiter_type == self.LIMITER_TYPE_JSON:
                return response_create("429", resp.get("429"), "Unusual activity detected")
            elif limiter_type == self.LIMITER_TYPE_MSGPACK:
                return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_PEER})
            else:
                return None

        data = callback(path, data, request_id, link_id, remote_identity, requested_at)

        if self.limiter_server:
            self.limiter_server.handle_size("server", len(data))

        if self.limiter_peer:
            self.limiter_peer.handle_size(str(remote_identity), len(data))

        if limiter:
            limiter.handle_size(str(remote_identity), len(data))

        return data


    def peer_connected(self, link):
        RNS.log("Server - Peer connected to "+str(self.destination), RNS.LOG_VERBOSE)

        link.set_link_closed_callback(self.peer_disconnected)
        link.set_remote_identified_callback(self.peer_identified)


    def peer_disconnected(self, link):
        RNS.log("Server - Peer disconnected from "+str(self.destination), RNS.LOG_VERBOSE)


    def peer_identified(self, link, identity):
        if not identity:
            link.teardown()


    def log(self, number=None, reason=None, key="", message="", dest="", status=False):
        if not self.config.has_section("log") or not self.config["log"].getboolean("enabled"):
            return

        if (status and self.config["log"].getboolean("success")) or (not status and self.config["log"].getboolean("error")):
            prefix = self.config["log"]["prefix"]
            try:
                _log = logs()
                _log.log_name = prefix+key
                _log.ts = int(time.time())
                _log.status = "success" if status else "error"
                _log.message = message
                _log.remarks = "RNS ID: "+dest if dest else ""
                self.db.add(_log)
                self.db.commit()
            except Exception as e:
                self.db.rollback()
