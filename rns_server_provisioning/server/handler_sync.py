##############################################################################################################
# Include


#### System ####
import time

#### Reticulum ####
# Install: pip3 install rns
# Source: https://markqvist.github.io
import RNS
import RNS.vendor.umsgpack as msgpack

#### Database ####
from sqlalchemy import func, asc, desc
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, OperationalError

#### Internal ####
from utils.utils import invitation_code_generate, invitation_code_verify, RateLimiter, ResponseError
from db.schema import (allocated_tasks, Announce, Device, EVM_address, InviteCode, Member, Service, task_definition,
                       device_status, device_type, member_role, member_state, sex)


##############################################################################################################
# HandlerSync Class


class HandlerSync:
    def __init__(self, owner):
        self.owner = owner

        if "limiter_enabled" in self.owner.config["handler_sync"] and  self.owner.config["handler_sync"].getboolean("limiter_enabled"):
            self.limiter = RateLimiter(int(self.owner.config["handler_sync"]["limiter_calls"]), int(self.owner.config["handler_sync"]["limiter_size"]), int(self.owner.config["handler_sync"]["limiter_duration"]))
        else:
            self.limiter = None

        if "account_limiter_enabled" in self.owner.config["handler_sync"] and self.owner.config["handler_sync"].getboolean("account_limiter_enabled"):
            self.account_limiter = RateLimiter(int(self.owner.config["handler_sync"]["account_limiter_calls"]), int(self.owner.config["handler_sync"]["account_limiter_size"]), int(self.owner.config["handler_sync"]["account_limiter_duration"]))
        else:
            self.account_limiter = None

        if "invitation_limiter_enabled" in self.owner.config["handler_sync"] and self.owner.config["handler_sync"].getboolean("invitation_limiter_enabled"):
            self.invitation_limiter = RateLimiter(int(self.owner.config["handler_sync"]["invitation_limiter_calls"]), int(self.owner.config["handler_sync"]["invitation_limiter_size"]), int(self.owner.config["handler_sync"]["invitation_limiter_duration"]))
        else:
            self.invitation_limiter = None

        if "service_limiter_enabled" in self.owner.config["handler_sync"] and self.owner.config["handler_sync"].getboolean("service_limiter_enabled"):
            self.service_limiter = RateLimiter(int(self.owner.config["handler_sync"]["service_limiter_calls"]), int(self.owner.config["handler_sync"]["service_limiter_size"]), int(self.owner.config["handler_sync"]["service_limiter_duration"]))
        else:
            self.service_limiter = None

        root = self.owner.config["handler_sync"]["root"]

        self.owner.register_request_handler(
            path=root+"sync",
            response_generator=self.sync,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_MSGPACK
        )


    #################################################
    # Auth                                          #
    #################################################


    def auth(self, dest, required=False):
        try:
            _member = self.owner.db.query(Member).filter_by(rns_id=dest).first()
            if _member:
                if _member.state == member_state.restricted or _member.state == member_state.onhold:
                    return False
                else:
                    return True
            else:
                if required:
                    return False
                else:
                    return True
        except Exception as e:
            RNS.log("auth - Error: "+str(e), RNS.LOG_ERROR)
            return False


    #################################################
    # Account                                       #
    #################################################


    def account_create(self, dest, account, blockchain, device):
        try:
            now = int(time.time())

            # Member
            _member = self.owner.db.query(Member).filter_by(rns_id=dest).first()
            if _member:
                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED, self.owner.TRANSACTION_STATE_REASON_MemberFound, "account_create", "Error: User already exists")
            _member = Member()
            _member.username = dest
            _member.display_name = account["display_name"]
            _member.email = account["email"] if account["email"] != "" else dest
            _member.password = account["password"]
            _member.did = blockchain[self.owner.BLOCKCHAIN_TOKEN_DID]["did"] if self.owner.BLOCKCHAIN_TOKEN_DID in blockchain and blockchain[self.owner.BLOCKCHAIN_TOKEN_DID]["did"] != "" else "did:morpheus:"+dest
            _member.rns_id = dest
            _member.hydra_wallet_address = blockchain[self.owner.BLOCKCHAIN_TOKEN_DID]["address"] if self.owner.BLOCKCHAIN_TOKEN_DID in blockchain and blockchain[self.owner.BLOCKCHAIN_TOKEN_DID]["address"] != "" else dest
            _member.first_name = ""
            _member.last_name = ""
            _member.registered_at = now
            _member.edited_at = now
            _member.role = member_role(self.owner.config["handler_sync"].getint("account_auth_role")).name
            _member.state = member_state(self.owner.config["handler_sync"].getint("account_auth_state")).name
            _member.city = account["city"]
            _member.state_name = account["state"]
            _member.country = account["country"]
            _member.language = account["language"]
            _member.dob = account["dob"]
            _member.sex = sex(account["sex"]).name
            _member.occupation = account["occupation"]
            _member.skills = account["skills"]
            _member.shop_goods = account["shop_goods"]
            _member.shop_services = account["shop_services"]
            _member.attributes = ",".join(account["attributes"])
            self.owner.db.add(_member)

            # Device
            _device = self.owner.db.query(Device).filter_by(device_id=device["id"]).first()
            if _device:
                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED, self.owner.TRANSACTION_STATE_REASON_DeviceFound, "account_create", "Error: Device already exists")
            _device = self.owner.db.query(Device).filter_by(device_rns_id=dest).first()
            if _device:
                _device.device_id = device["id"]
                _device.device_display_name = device["name"]
                _device.edited_at = now
            else:
                _device = Device()
                _device.device_id = device["id"]
                _device.device_rns_id = dest
                _device.device_associated_user_id = dest
                _device.device_display_name = device["name"]
                _device.registered_at = now
                _device.edited_at = now
                _device._type = device_type(self.owner.config["handler_sync"].getint("account_device_type")).name
                _device.status = device_status(self.owner.config["handler_sync"].getint("account_device_status")).name
                self.owner.db.add(_device)

            # EVM address
            if self.owner.BLOCKCHAIN_TOKEN_PRIMARY in blockchain and blockchain[self.owner.BLOCKCHAIN_TOKEN_PRIMARY]["address"] != "":
                _evm_address = self.owner.db.query(EVM_address).filter_by(user=dest).first()
                if _evm_address:
                    raise ResponseError(self.owner.TRANSACTION_STATE_FAILED, self.owner.TRANSACTION_STATE_REASON_EntryFound, "account_create", "Error: EVM address already exists")
                _evm_address = EVM_address()
                _evm_address.address = blockchain[self.owner.BLOCKCHAIN_TOKEN_PRIMARY]["address"]
                _evm_address.user = dest
                self.owner.db.add(_evm_address)
                # TODO: Add EVM address to blockchain

            # Invitation
            if account["invite"] and invitation_code_verify(account["invite"]):
                _invite_code = self.owner.db.query(InviteCode).filter_by(code=account["invite"]).first()
                if _invite_code and _invite_code.inviter != dest and _invite_code.is_valid and not _invite_code.used_at:
                    _invite_code.invitee = dest
                    _invite_code.used_at = now

            # Tasks
            _tasks = self.owner.db.query(allocated_tasks).filter_by(member_id=dest).all()
            if _tasks:
                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED, self.owner.TRANSACTION_STATE_REASON_TaskFound, "account_create", "Error: Tasks already exists")

            _task_list = self.owner.db.query(task_definition).all()
            for i in _task_list:
                _task = allocated_tasks()
                _task.member_id = dest
                _task.task_id = i.task_id
                _task.task_issue_ts = now
                _task.task_due_ts = now + i.task_deadline
                self.owner.db.add(_task)

            self.owner.db.commit()

        except ResponseError as e:
            self.owner.db.rollback()
            raise ResponseError(e.error_number, e.error_reason, e.error_key, e.error_message)

        except IntegrityError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Conflict, "account_create", "IntegrityError: "+str(e))

        except OperationalError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_ServiceUnavailable, "account_create", "OperationalError: "+str(e))

        except SQLAlchemyError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "account_create", "SQLAlchemyError: "+str(e))

        except TypeError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_InvalidData, "account_create", "TypeError: "+str(e))

        except Exception as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "account_create", "Error: "+str(e))


    def account_delete(self, dest):
        try:
            now = int(time.time())

            # Member
            _member = self.owner.db.query(Member).filter_by(rns_id=dest).first()
            if _member:
                self.owner.db.delete(_member)

            # Device
            _device = self.owner.db.query(Device).filter_by(device_rns_id=dest).first()
            if _device:
                self.owner.db.delete(_device)

            # EVM address
            _evm_address = self.owner.db.query(EVM_address).filter_by(user=dest).first()
            if _evm_address:
                self.owner.db.delete(_evm_address)

            # Invitation
            _invite_codes = self.owner.db.query(InviteCode).filter_by(inviter=dest).filter(InviteCode.used_at.is_(None))
            if _invite_codes:
                _invite_codes.delete()

            # Service
            _services = self.owner.db.query(Service).filter_by(owner=dest)
            if _services:
                _services.delete()

            self.owner.db.commit()

        except ResponseError as e:
            self.owner.db.rollback()
            raise ResponseError(e.error_number, e.error_reason, e.error_key, e.error_message)

        except IntegrityError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Conflict, "account_delete", "IntegrityError: "+str(e))

        except OperationalError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_ServiceUnavailable, "account_delete", "OperationalError: "+str(e))

        except SQLAlchemyError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "account_delete", "SQLAlchemyError: "+str(e))

        except TypeError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_InvalidData, "account_delete", "TypeError: "+str(e))

        except Exception as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "account_delete", "Error: "+str(e))


    def account_edit(self, dest, account, blockchain, device):
        try:
            now = int(time.time())

            # Member
            _member = self.owner.db.query(Member).filter_by(rns_id=dest).first()
            if not _member:
                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED, self.owner.TRANSACTION_STATE_REASON_MemberNotFound, "account_edit", "Error: User does not exist")
            _member.username = dest
            _member.display_name = account["display_name"]
            _member.email = account["email"] if account["email"] != "" else dest
            _member.password = account["password"]
            _member.edited_at = now
            _member.city = account["city"]
            _member.state_name = account["state"]
            _member.country = account["country"]
            _member.language = account["language"]
            _member.dob = account["dob"]
            _member.sex = sex(account["sex"]).name
            _member.occupation = account["occupation"]
            _member.skills = account["skills"]
            _member.shop_goods = account["shop_goods"]
            _member.shop_services = account["shop_services"]
            _member.attributes = ",".join(account["attributes"])

            # Device
            _device = self.owner.db.query(Device).filter_by(device_rns_id=dest).first()
            if not _device:
                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED, self.owner.TRANSACTION_STATE_REASON_DeviceNotFound, "account_edit", "Error: Device does not exist")
            _device.device_id = device["id"]
            _device.device_display_name = device["name"]
            _device.edited_at = now

            # Invitation
            if account["invite"] and invitation_code_verify(account["invite"]):
                _invite_code = self.owner.db.query(InviteCode).filter_by(invitee=dest).first()
                if not _invite_code:
                    _invite_code = self.owner.db.query(InviteCode).filter_by(code=account["invite"]).first()
                    if _invite_code and _invite_code.inviter != dest and _invite_code.is_valid and not _invite_code.used_at:
                        _invite_code.invitee = dest
                        _invite_code.used_at = now

            self.owner.db.commit()

        except ResponseError as e:
            self.owner.db.rollback()
            raise ResponseError(e.error_number, e.error_reason, e.error_key, e.error_message)

        except IntegrityError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Conflict, "account_edit", "IntegrityError: "+str(e))

        except OperationalError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_ServiceUnavailable, "account_edit", "OperationalError: "+str(e))

        except SQLAlchemyError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "account_edit", "SQLAlchemyError: "+str(e))

        except TypeError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_InvalidData, "account_edit", "TypeError: "+str(e))

        except Exception as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "account_edit", "Error: "+str(e))


    def account_get(self, dest, ts):
        try:
            _member = self.owner.db.query(Member).filter_by(rns_id=dest).filter(Member.edited_at>ts).first()
            if not _member:
                return None
            else:
                data = {
                    "display_name": _member.display_name,
                    "email": _member.email if _member.email != dest else "",
                    "ts_add": _member.registered_at,
                    "ts_edit": _member.edited_at,
                    "auth_role": _member.role.value,
                    "auth_state": _member.state.value,
                    "city": _member.city,
                    "state": _member.state_name,
                    "country": _member.country,
                    "language": _member.language,
                    "dob": _member.dob,
                    "sex": _member.sex.value,
                    "occupation": _member.occupation,
                    "skills": _member.skills,
                    "shop_goods": _member.shop_goods,
                    "shop_services": _member.shop_services,
                    "attributes": _member.attributes.split(",") if _member.attributes else [],
                }
                if len(_member.invitee_codes) > 0:
                    data["invite"] = _member.invitee_codes[0].code
                    data["invite_inviter"] = _member.invitee_codes[0].inviter
                    data["invite_state"] = self.owner.ACCOUNT_INVITE_STATE_SUCCESSFULL
                else:
                    data["invite_inviter"] = ""
                    data["invite_state"] = self.owner.ACCOUNT_INVITE_STATE_NONE
                return data

        except ResponseError as e:
            self.owner.db.rollback()
            RNS.log(str(e), RNS.LOG_ERROR)
            return None

        except IntegrityError as e:
            self.owner.db.rollback()
            RNS.log("account_get - IntegrityError: "+str(e), RNS.LOG_ERROR)
            return None

        except OperationalError as e:
            self.owner.db.rollback()
            RNS.log("account_get - OperationalError: "+str(e), RNS.LOG_ERROR)
            return None

        except SQLAlchemyError as e:
            self.owner.db.rollback()
            RNS.log("account_get - SQLAlchemyError: "+str(e), RNS.LOG_ERROR)
            return None

        except TypeError as e:
            self.owner.db.rollback()
            RNS.log("account_get - TypeError: "+str(e), RNS.LOG_ERROR)
            return None

        except Exception as e:
            self.owner.db.rollback()
            RNS.log("account_get - Error: "+str(e), RNS.LOG_ERROR)
            return None


    def account_restore(self, dest, device):
        try:
            now = int(time.time())

            # Member
            _member = self.owner.db.query(Member).filter_by(rns_id=dest).first()
            if not _member:
                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED, self.owner.TRANSACTION_STATE_REASON_MemberNotFound, "account_restore", "Error: User does not exist")

            # Device
            _device = self.owner.db.query(Device).filter_by(device_id=device["id"]).filter(Device.device_rns_id!=dest).first()
            if _device:
                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED, self.owner.TRANSACTION_STATE_REASON_DeviceFound, "account_restore", "Error: Device already exists")
            _device = self.owner.db.query(Device).filter_by(device_rns_id=dest).first()
            if _device:
                _device.device_id = device["id"]
                _device.device_display_name = device["name"]
                _device.edited_at = now
            else:
                _device = Device()
                _device.device_id = device["id"]
                _device.device_rns_id = dest
                _device.device_associated_user_id = dest
                _device.device_display_name = device["name"]
                _device.registered_at = now
                _device.edited_at = now
                _device._type = device_type(self.owner.config["handler_sync"].getint("account_device_type")).name
                _device.status = device_status(self.owner.config["handler_sync"].getint("account_device_status")).name
                self.owner.db.add(_device)

            self.owner.db.commit()

        except ResponseError as e:
            self.owner.db.rollback()
            raise ResponseError(e.error_number, e.error_reason, e.error_key, e.error_message)

        except IntegrityError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Conflict, "account_restore", "IntegrityError: "+str(e))

        except OperationalError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_ServiceUnavailable, "account_restore", "OperationalError: "+str(e))

        except SQLAlchemyError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "account_restore", "SQLAlchemyError: "+str(e))

        except TypeError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_InvalidData, "account_restore", "TypeError: "+str(e))

        except Exception as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "account_restore", "Error: "+str(e))


    #################################################
    # Invitation                                    #
    #################################################


    def invitation_create(self, dest):
        try:
            now = int(time.time())

            for i in range(10):
                code = invitation_code_generate()
                if not self.owner.db.query(InviteCode).filter_by(code=code).first():
                    break

            _invite_code = InviteCode()
            _invite_code.code = code
            _invite_code.inviter = dest
            _invite_code.generated_at = now
            self.owner.db.add(_invite_code)

            self.owner.db.commit()

            return {
                _invite_code.code: _invite_code.generated_at
            }

        except ResponseError as e:
            raise ResponseError(e.error_number, e.error_reason, e.error_key, e.error_message)

        except IntegrityError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Conflict, "invitation_create", "IntegrityError: "+str(e))

        except OperationalError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_ServiceUnavailable, "invitation_create", "OperationalError: "+str(e))

        except SQLAlchemyError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "invitation_create", "SQLAlchemyError: "+str(e))

        except TypeError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_InvalidData, "invitation_create", "TypeError: "+str(e))

        except Exception as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "invitation_create", "Error: "+str(e))


    def invitation_delete(self, dest, data):
        try:
            now = int(time.time())

            if data["code"] != None:
                _invite_code = self.owner.db.query(InviteCode).filter_by(code=data["code"], inviter=dest).filter(InviteCode.used_at.is_(None)).first()
                if _invite_code:
                    self.owner.db.delete(_invite_code)
            else:
                _invite_codes = self.owner.db.query(InviteCode).filter_by(inviter=dest).filter(InviteCode.used_at.is_(None))
                if _invite_codes:
                    _invite_codes.delete()

            self.owner.db.commit()

        except ResponseError as e:
            self.owner.db.rollback()
            raise ResponseError(e.error_number, e.error_reason, e.error_key, e.error_message)

        except IntegrityError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Conflict, "invitation_delete", "IntegrityError: "+str(e))

        except OperationalError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_ServiceUnavailable, "invitation_delete", "OperationalError: "+str(e))

        except SQLAlchemyError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "invitation_delete", "SQLAlchemyError: "+str(e))

        except TypeError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_InvalidData, "invitation_delete", "TypeError: "+str(e))

        except Exception as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "invitation_delete", "Error: "+str(e))


    def invitation_list(self, dest, ts):
        try:
            _invite_codes = self.owner.db.query(InviteCode).filter_by(inviter=dest).order_by(asc(InviteCode.generated_at)).all()
            if not _invite_codes:
                return None
            else:
                data = {}
                for _invite_code in _invite_codes:
                    _ts = _invite_code.used_at if _invite_code.used_at else _invite_code.generated_at
                    if _ts > ts:
                        data[_invite_code.code] = {
                            "dest": _invite_code.invitee,
                            "ts": _ts,
                        }
                return data

        except ResponseError as e:
            self.owner.db.rollback()
            RNS.log(str(e), RNS.LOG_ERROR)
            return []

        except IntegrityError as e:
            self.owner.db.rollback()
            RNS.log("invitation_list - IntegrityError: "+str(e), RNS.LOG_ERROR)
            return []

        except OperationalError as e:
            self.owner.db.rollback()
            RNS.log("invitation_list - OperationalError: "+str(e), RNS.LOG_ERROR)
            return []

        except SQLAlchemyError as e:
            self.owner.db.rollback()
            RNS.log("invitation_list - SQLAlchemyError: "+str(e), RNS.LOG_ERROR)
            return []

        except TypeError as e:
            self.owner.db.rollback()
            RNS.log("invitation_list - TypeError: "+str(e), RNS.LOG_ERROR)
            return []

        except Exception as e:
            self.owner.db.rollback()
            RNS.log("invitation_list - Error: "+str(e), RNS.LOG_ERROR)
            return []


    #################################################
    # Service                                       #
    #################################################


    def service_create(self, dest, data):
        try:
            now = int(time.time())

            _service = self.owner.db.query(Service).filter_by(rns_id=data["dest"]).first()
            if _service:
                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED, self.owner.TRANSACTION_STATE_REASON_EntryFound, "service_create", "Error: Service already exists")

            _announce = self.owner.db.query(Announce).filter_by(dest=data["dest"], dest_type=data["type"], owner=dest).first()
            if not _announce:
                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_EntryNotFound, "service_create", "Error: Announce does not exist")

            _service = Service()
            _service.rns_id = data["dest"]
            _service.display_name = data["display_name"]
            _service.city = data["location_city"]
            _service.state_name = data["location_state"]
            _service.country = data["location_country"]
            _service._type = data["type"]
            _service.owner = dest
            _service.ts_add = now
            _service.ts_edit = now
            self.owner.db.add(_service)

            self.owner.db.commit()

        except ResponseError as e:
            self.owner.db.rollback()
            raise ResponseError(e.error_number, e.error_reason, e.error_key, e.error_message)

        except IntegrityError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Conflict, "service_create", "IntegrityError: "+str(e))

        except OperationalError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_ServiceUnavailable, "service_create", "OperationalError: "+str(e))

        except SQLAlchemyError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "service_create", "SQLAlchemyError: "+str(e))

        except TypeError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_InvalidData, "service_create", "TypeError: "+str(e))

        except Exception as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "service_create", "Error: "+str(e))


    def service_delete(self, dest, data):
        try:
            now = int(time.time())

            _service = self.owner.db.query(Service).filter_by(rns_id=data["dest"], owner=dest).first()
            if _service:
                self.owner.db.delete(_service)

            self.owner.db.commit()

        except ResponseError as e:
            self.owner.db.rollback()
            raise ResponseError(e.error_number, e.error_reason, e.error_key, e.error_message)

        except IntegrityError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Conflict, "service_delete", "IntegrityError: "+str(e))

        except OperationalError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_ServiceUnavailable, "service_delete", "OperationalError: "+str(e))

        except SQLAlchemyError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "service_delete", "SQLAlchemyError: "+str(e))

        except TypeError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_InvalidData, "service_delete", "TypeError: "+str(e))

        except Exception as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "service_delete", "Error: "+str(e))


    def service_edit(self, dest, data):
        try:
            now = int(time.time())

            _service = self.owner.db.query(Service).filter_by(rns_id=data["dest"], owner=dest).first()
            if not _service:
                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED, self.owner.TRANSACTION_STATE_REASON_EntryNotFound, "service_edit", "Error: Service does not exist")

            _service.display_name = data["display_name"]
            _service.city = data["location_city"]
            _service.state_name = data["location_state"]
            _service.country = data["location_country"]
            _service._type = data["type"]
            _service.ts_edit = now

            self.owner.db.commit()

        except ResponseError as e:
            self.owner.db.rollback()
            raise ResponseError(e.error_number, e.error_reason, e.error_key, e.error_message)

        except IntegrityError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Conflict, "service_edit", "IntegrityError: "+str(e))

        except OperationalError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_ServiceUnavailable, "service_edit", "OperationalError: "+str(e))

        except SQLAlchemyError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "service_edit", "SQLAlchemyError: "+str(e))

        except TypeError as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_InvalidData, "service_edit", "TypeError: "+str(e))

        except Exception as e:
            self.owner.db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Internal, "service_edit", "Error: "+str(e))


    def service_list(self, dest, ts):
        try:
            _services = self.owner.db.query(Service).filter_by(owner=dest).filter(Service.ts_edit>ts).order_by(asc(Service.ts_edit)).all()
            if not _services:
                return None
            else:
                data = {}
                for _service in _services:
                    data[_service.rns_id] = {
                        "display_name": _service.display_name,
                        "location_city": _service.city,
                        "location_state": _service.state_name,
                        "location_country": _service.country,
                        "type": _service._type,
                        "ts_add": _service.ts_add,
                        "ts_edit": _service.ts_edit,
                        "state": self.owner.SERVICE_STATE_SUCCESSFULL,
                    }
                return data

        except ResponseError as e:
            self.owner.db.rollback()
            RNS.log(str(e), RNS.LOG_ERROR)
            return []

        except IntegrityError as e:
            self.owner.db.rollback()
            RNS.log("service_list - IntegrityError: "+str(e), RNS.LOG_ERROR)
            return []

        except OperationalError as e:
            self.owner.db.rollback()
            RNS.log("service_list - OperationalError: "+str(e), RNS.LOG_ERROR)
            return []

        except SQLAlchemyError as e:
            self.owner.db.rollback()
            RNS.log("service_list - SQLAlchemyError: "+str(e), RNS.LOG_ERROR)
            return []

        except TypeError as e:
            self.owner.db.rollback()
            RNS.log("service_list - TypeError: "+str(e), RNS.LOG_ERROR)
            return []

        except Exception as e:
            self.owner.db.rollback()
            RNS.log("service_list - Error: "+str(e), RNS.LOG_ERROR)
            return []


    #################################################
    # Sync                                          #
    #################################################


    def sync(self, path, data, request_id, link_id, remote_identity, requested_at):
        RNS.log("Server - HandlerSync", RNS.LOG_DEBUG)
        RNS.log(data, RNS.LOG_EXTREME)

        if not data:
            return msgpack.packb({self.owner.KEY_RESULT: self.owner.RESULT_NO_DATA})

        dest = RNS.hexrep(RNS.Destination.hash_from_name_and_identity(self.owner.aspect_filter_conv, remote_identity), delimit=False)

        if not self.auth(dest, False):
            return msgpack.packb({self.owner.KEY_RESULT: self.owner.RESULT_NO_RIGHT})

        data_return = {}

        try:
            data_return[self.owner.KEY_RESULT] = self.owner.RESULT_OK

            # Transaction
            if self.owner.KEY_T in data:
                transactions = {}
                transaction_list = dict(sorted(data[self.owner.KEY_T].items(), key=lambda item: item[1][self.owner.KEY_T_INDEX]))
                for transaction_id, transaction in transaction_list.items():
                    try:
                        if self.owner.KEY_T_TYPE not in transaction or self.owner.KEY_T_DATA not in transaction:
                            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED, self.owner.TRANSACTION_STATE_REASON_InvalidData, "transaction", "Missing type/data")

                        transaction_data = transaction[self.owner.KEY_T_DATA]

                        # Account - Create
                        if transaction[self.owner.KEY_T_TYPE] == self.owner.TRANSACTION_TYPE_ACCOUNT_CREATE:
                            if not self.owner.config["handler_sync"].getboolean("account_create"):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Disabled, "account_create", "Feature disabled")
                            if self.account_limiter and not self.account_limiter.handle(dest):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_LimitPeer, "account_create", "Limit peer")

                            self.account_create(dest=dest, account=transaction_data["account"], blockchain=transaction_data["blockchain"], device=transaction_data["device"])
                            self.owner.log(key="account_create", message="", dest=dest, status=True)
                            data[self.owner.KEY_A] = {self.owner.KEY_A_TS: 0}

                        # Account - Delete
                        if transaction[self.owner.KEY_T_TYPE] == self.owner.TRANSACTION_TYPE_ACCOUNT_DELETE:
                            if not self.owner.config["handler_sync"].getboolean("account_delete"):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Disabled, "account_delete", "Feature disabled")
                            if self.account_limiter and not self.account_limiter.handle(dest):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_LimitPeer, "account_delete", "Limit peer")

                            self.account_delete(dest=dest)
                            self.owner.log(key="account_delete", message="", dest=dest, status=True)
                            data[self.owner.KEY_A] = {self.owner.KEY_A_TS: 0}

                        # Account - Edit
                        if transaction[self.owner.KEY_T_TYPE] == self.owner.TRANSACTION_TYPE_ACCOUNT_EDIT:
                            if not self.owner.config["handler_sync"].getboolean("account_edit"):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Disabled, "account_edit", "Feature disabled")
                            if not self.auth(dest, True):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_NoRight, "account_edit", "No right")
                            if self.account_limiter and not self.account_limiter.handle(dest):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_LimitPeer, "account_edit", "Limit peer")

                            self.account_edit(dest=dest, account=transaction_data["account"], blockchain=transaction_data["blockchain"], device=transaction_data["device"])
                            self.owner.log(key="account_edit", message="", dest=dest, status=True)

                        # Account - Restore
                        if transaction[self.owner.KEY_T_TYPE] == self.owner.TRANSACTION_TYPE_ACCOUNT_RESTORE:
                            if not self.owner.config["handler_sync"].getboolean("account_restore"):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Disabled, "account_restore", "Feature disabled")
                            if self.account_limiter and not self.account_limiter.handle(dest):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_LimitPeer, "account_restore", "Limit peer")

                            self.account_restore(dest=dest, device=transaction_data["device"])
                            self.owner.log(key="account_restore", message="", dest=dest, status=True)
                            data[self.owner.KEY_A] = {self.owner.KEY_A_TS: 0}

                        # Invitation - Create
                        if transaction[self.owner.KEY_T_TYPE] == self.owner.TRANSACTION_TYPE_INVITATION_CREATE:
                            if not self.owner.config["handler_sync"].getboolean("invitation_create"):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Disabled, "invitation_create", "Feature disabled")
                            if not self.auth(dest, True):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_NoRight, "invitation_create", "No right")
                            if self.invitation_limiter and not self.invitation_limiter.handle(dest):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_LimitPeer, "invitation_create", "Limit peer")

                            self.invitation_create(dest=dest)
                            self.owner.log(key="invitation_create", message="", dest=dest, status=True)

                        # Invitation - Delete
                        if transaction[self.owner.KEY_T_TYPE] == self.owner.TRANSACTION_TYPE_INVITATION_DELETE:
                            if not self.owner.config["handler_sync"].getboolean("invitation_delete"):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Disabled, "invitation_delete", "Feature disabled")
                            if not self.auth(dest, True):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_NoRight, "invitation_delete", "No right")
                            if self.invitation_limiter and not self.invitation_limiter.handle(dest):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_LimitPeer, "invitation_delete", "Limit peer")

                            self.invitation_delete(dest=dest, data=transaction_data)
                            self.owner.log(key="invitation_delete", message="", dest=dest, status=True)

                        # Service - Create
                        if transaction[self.owner.KEY_T_TYPE] == self.owner.TRANSACTION_TYPE_SERVICE_CREATE:
                            if not self.owner.config["handler_sync"].getboolean("service_create"):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Disabled, "service_create", "Feature disabled")
                            if not self.auth(dest, True):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_NoRight, "service_create", "No right")
                            if self.service_limiter and not self.service_limiter.handle(dest):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_LimitPeer, "service_create", "Limit peer")

                            self.service_create(dest=dest, data=transaction_data)
                            self.owner.log(key="service_create", message="", dest=dest, status=True)

                        # Service - Edit
                        if transaction[self.owner.KEY_T_TYPE] == self.owner.TRANSACTION_TYPE_SERVICE_EDIT:
                            if not self.owner.config["handler_sync"].getboolean("service_edit"):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Disabled, "service_edit", "Feature disabled")
                            if not self.auth(dest, True):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_NoRight, "service_edit", "No right")
                            if self.service_limiter and not self.service_limiter.handle(dest):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_LimitPeer, "service_edit", "Limit peer")

                            self.service_edit(dest=dest, data=transaction_data)
                            self.owner.log(key="service_edit", message="", dest=dest, status=True)

                        # Service - Delete
                        if transaction[self.owner.KEY_T_TYPE] == self.owner.TRANSACTION_TYPE_SERVICE_DELETE:
                            if not self.owner.config["handler_sync"].getboolean("service_delete"):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_Disabled, "service_delete", "Feature disabled")
                            if not self.auth(dest, True):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_NoRight, "service_delete", "No right")
                            if self.service_limiter and not self.service_limiter.handle(dest):
                                raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.TRANSACTION_STATE_REASON_LimitPeer, "service_delete", "Limit peer")

                            self.service_delete(dest=dest, data=transaction_data)
                            self.owner.log(key="service_delete", message="", dest=dest, status=True)

                        transactions[transaction_id] = {self.owner.KEY_T_STATE: self.owner.TRANSACTION_STATE_SUCCESSFULL}

                    except ResponseError as e:
                        RNS.log("Server - HandlerSync - Error: "+str(e), RNS.LOG_ERROR)
                        self.owner.log(number=e.error_number, reason=e.error_reason, key=e.error_key, message=e.error_message, dest=dest, status=False)
                        transactions[transaction_id] = {self.owner.KEY_T_STATE: e.error_number, self.owner.KEY_T_STATE_REASON: e.error_reason}
                        data_return[self.owner.KEY_RESULT] = self.owner.RESULT_PARTIAL

                    except TypeError as e:
                        RNS.log("Server - HandlerSync - Error: "+str(e), RNS.LOG_ERROR)
                        self.owner.log(number=self.owner.TRANSACTION_STATE_FAILED, reason=self.owner.TRANSACTION_STATE_REASON_InvalidData, key="sync", message=str(e), dest=dest, status=False)
                        transactions[transaction_id] = {self.owner.KEY_T_STATE: self.owner.TRANSACTION_STATE_FAILED, self.owner.KEY_T_STATE_REASON: self.owner.TRANSACTION_STATE_REASON_InvalidData}
                        data_return[self.owner.KEY_RESULT] = self.owner.RESULT_PARTIAL

                    except Exception as e:
                        RNS.log("Server - HandlerSync - Error: "+str(e), RNS.LOG_ERROR)
                        self.owner.log(number=self.owner.TRANSACTION_STATE_FAILED_TMP, reason=self.owner.TRANSACTION_STATE_REASON_Internal, key="sync", message=str(e), dest=dest, status=False)
                        transactions[transaction_id] = {self.owner.KEY_T_STATE: self.owner.TRANSACTION_STATE_FAILED_TMP, self.owner.KEY_T_STATE_REASON: self.owner.TRANSACTION_STATE_REASON_Internal}
                        data_return[self.owner.KEY_RESULT] = self.owner.RESULT_PARTIAL

                if len(transactions) > 0:
                    data_return[self.owner.KEY_T] = transactions

            # Account
            if self.owner.KEY_A in data:
                entry = self.account_get(dest=dest, ts=data[self.owner.KEY_A][self.owner.KEY_A_TS])
                if entry:
                    data_return[self.owner.KEY_A] = {
                        self.owner.KEY_A_DATA: entry
                    }

            # Invitation
            if self.owner.KEY_I in data:
                entry = self.invitation_list(dest=dest, ts=data[self.owner.KEY_I][self.owner.KEY_I_TS])
                if entry and len(entry) > 0:
                    data_return[self.owner.KEY_I] = {
                        self.owner.KEY_I_DATA: entry
                    }

            # Service
            if self.owner.KEY_S in data:
                entry = self.service_list(dest=dest, ts=data[self.owner.KEY_S][self.owner.KEY_S_TS])
                if entry and len(entry) > 0:
                    data_return[self.owner.KEY_S] = {
                        self.owner.KEY_S_DATA: entry
                    }

            # Task
            if self.owner.KEY_TA in data:
                entry = self.task_list(dest=dest, ts=data[self.owner.KEY_TA][self.owner.KEY_TA_TS])
                if entry and len(entry) > 0:
                    data_return[self.owner.KEY_TA] = {
                        self.owner.KEY_TA_DATA: entry
                    }

        except ResponseError as e:
            RNS.log("Server - HandlerSync", RNS.LOG_ERROR)
            RNS.trace_exception(e)
            data_return[self.owner.KEY_RESULT] = e.error_number
            data_return[self.owner.KEY_RESULT_REASON] = e.error_reason

        except TypeError as e:
            RNS.log("Server - HandlerSync", RNS.LOG_ERROR)
            RNS.trace_exception(e)
            data_return[self.owner.KEY_RESULT] = self.owner.RESULT_ERROR

        except Exception as e:
            RNS.log("Server - HandlerSync", RNS.LOG_ERROR)
            RNS.trace_exception(e)
            data_return[self.owner.KEY_RESULT] = self.owner.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        return data_return


    #################################################
    # Task                                          #
    #################################################


    def task_list(self, dest, ts):
        try:
            _tasks = self.owner.db.query(allocated_tasks).filter_by(member_id=dest).all()
            if not _tasks:
                return None
            else:
                data = {}
                for _task in _tasks:
                    _ts = _task.task_completed_ts if _task.task_completed_ts else _task.task_issue_ts
                    if _ts > ts:
                        data[_task.task_id] = {
                            "state": True if _task.task_completed_ts else False,
                            "ts": _ts,
                        }
                return data

        except ResponseError as e:
            self.owner.db.rollback()
            RNS.log(str(e), RNS.LOG_ERROR)
            return []

        except IntegrityError as e:
            self.owner.db.rollback()
            RNS.log("task_list - IntegrityError: "+str(e), RNS.LOG_ERROR)
            return []

        except OperationalError as e:
            self.owner.db.rollback()
            RNS.log("task_list - OperationalError: "+str(e), RNS.LOG_ERROR)
            return []

        except SQLAlchemyError as e:
            self.owner.db.rollback()
            RNS.log("task_list - SQLAlchemyError: "+str(e), RNS.LOG_ERROR)
            return []

        except TypeError as e:
            self.owner.db.rollback()
            RNS.log("task_list - TypeError: "+str(e), RNS.LOG_ERROR)
            return []

        except Exception as e:
            self.owner.db.rollback()
            RNS.log("task_list - Error: "+str(e), RNS.LOG_ERROR)
            return []
