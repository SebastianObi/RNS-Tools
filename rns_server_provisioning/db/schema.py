from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, validates
from sqlalchemy.types import TypeDecorator, String as stri
import enum, re, json, string, random, time
from datetime import datetime as DT
from sqlalchemy.inspection import inspect
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy import (
    Column,
    Integer,
    String,
    UniqueConstraint,
    Boolean,
    ForeignKey,
    Enum as eum,
    Numeric,
    CheckConstraint,
    Float,
    LargeBinary
)

Base = declarative_base()

MEMBER_IMMUTABLE_FIELDS = {"id", "username", "email", "did", "rns_id"}

DEVICE_IMMUTABLE_FIELDS = {
    "id",
    "device_id",
    "device_rns_id",
    "device_associated_user_id",
}


# custom datatypes
class DID(TypeDecorator):
    impl = stri

    def process_bind_param(self, value, dialect):
        if value is None:
            return value

        if not value.startswith("did:morpheus:"):
            raise ValueError("Invalid DID format. Must start with 'did:morpheus:'")
        return value

    def process_result_value(self, value, dialect):
        return value


class EVMAddress(TypeDecorator):
    impl = stri(42)

    def process_bind_param(self, value, dialect):
        if value is not None:
            if not re.match(r"^0x[a-fA-F0-9]{40}$", value):
                raise ValueError(
                    'Invalid EVM public key format. Should be in hexadecimal format starting with "0x"'
                )
        return value

    def process_result_value(self, value, dialect):
        return value


# custom enums
class member_role(enum.Enum):
    aspirant = 0
    admin = 1
    moderator = 2
    user = 3


class member_state(enum.Enum):
    registered = 0
    accepted = 1
    restricted = 2
    onhold = 3


class device_status(enum.Enum):
    registered = 0
    active = 1
    deactive = 2
    onhold = 3


class sex(enum.Enum):
    none = 0
    female = 1
    male = 2


class device_type(enum.Enum):
    user = 0
    node = 1
    server = 2
    others = 3


class token_status(enum.Enum):
    inactive = 0
    active = 1


# triggers
characters = string.ascii_uppercase + string.digits


def generate_random_string(length=5):
    return "".join(random.choices(characters, k=length))


# defining tables
class Member(Base):
    __tablename__ = "members"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    display_name = Column(String)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)

    did = Column(DID, unique=True, nullable=False)
    rns_id = Column(String(32), unique=True, nullable=False)
    hydra_wallet_address = Column(String)

    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100))

    registered_at = Column(Integer, default=lambda: int(time.time()), nullable=False)
    edited_at = Column(
        Integer,
        default=lambda: int(time.time()),
        onupdate=lambda: int(time.time()),
        nullable=False,
    )
    approved_at = Column(Integer, nullable=True)

    role = Column(
        eum(member_role), nullable=False, default=member_role.aspirant
    )  # 0=Aspirant, 1=Admin, 2=Moderator, 3=User
    state = Column(
        eum(member_state), nullable=False, default=member_state.registered
    )  # 0=registered, 1=Accepted, 2=Restricted, 3=onhold

    address1 = Column(String(100))
    address2 = Column(String(100))
    city = Column(String(100))
    state_name = Column(String(5))
    country = Column(String(2))
    zip_code = Column(String(10))
    language = Column(String(2))
    dob = Column(Integer, nullable=True)
    sex = Column(eum(sex), nullable=False)  # 0=None, 1=Female, 2=Male
    occupation = Column(String)
    skills = Column(String)

    shop_goods = Column(String, nullable=True)
    shop_services = Column(String, nullable=True)

    attributes = Column(String, nullable=True)

    notes_by_admin = Column(String(250), nullable=True)

    __table_args__ = (
        UniqueConstraint(username, email, did, rns_id, hydra_wallet_address),
    )

    invitee_codes = relationship(
        "InviteCode", back_populates="invitee_member", foreign_keys="InviteCode.invitee"
    )
    inviter_codes = relationship(
        "InviteCode", back_populates="inviter_member", foreign_keys="InviteCode.inviter"
    )

    user_id_for_evm_address = relationship(
        "EVM_address", back_populates="member_id", foreign_keys="EVM_address.user"
    )
    evm_addresses = relationship(
        "EVM_address",
        back_populates="member",
        foreign_keys="EVM_address.user",
        overlaps="user_id_for_evm_address",
    )

    user_id_for_faucets = relationship(
        "faucet_requests",
        back_populates="member_id",
        foreign_keys="faucet_requests.user",
    )

    user_id_for_tasks = relationship(
        "allocated_tasks",
        back_populates="user",
        foreign_keys="allocated_tasks.member_id",
    )

    user_id_for_device_table = relationship(
        "Device",
        back_populates="member_id",
        foreign_keys="Device.device_associated_user_id",
    )
    devices = relationship(
        "Device",
        back_populates="member",
        foreign_keys="Device.device_associated_user_id",
        overlaps="user_id_for_device_table",
    )

    user_id_for_service = relationship(
        "Service",
        back_populates="user",
        foreign_keys="Service.owner",
    )

    def to_json(self):
        # self.__dict__.pop('_sa_instance_state', None)
        # self.__dict__.pop('password', None)
        # return self.__dict__ #json.dumps(self.__dict__, cls=json_encoder)

        attributes = {
            c.key: getattr(self, c.key) for c in inspect(self).mapper.column_attrs
        }
        for key, value in attributes.items():
            if isinstance(
                value, enum.Enum
            ):  # Check if the value is an instance of Enum
                attributes[key] = value.name  # Convert to enum name (string)
        attributes.pop("password", None)
        attributes.pop("_sa_instance_state", None)
        return attributes

    # @staticmethod
    # def from_json(data:dict,rns_identity):
    #     _member = Member()
    #     for key in data.keys():
    #         if key == 'password':
    #             _member.__setattr__(key, password_hash_get(data.get(key)))
    #             continue
    #         _member.__setattr__(key, data.get(key))
    #     _member.__setattr__('rns_id', str(rns_identity))

    #     return _member

    @staticmethod
    def from_json(data: dict):
        _member = Member()
        for key, value in data.items():
            if key in {"role", "state", "sex"}:
                # Convert string back to enum value
                enum_class = {"role": member_role, "state": member_state, "sex": sex}[
                    key
                ]
                value = enum_class[value]
            _member.__setattr__(key, value)
        return _member


class InviteCode(Base):
    __tablename__ = "invites"

    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column(String(8), nullable=False, unique=True)
    inviter = Column(
        String(32), ForeignKey("members.rns_id", onupdate="CASCADE"), nullable=False
    )
    invitee = Column(
        String(32), ForeignKey("members.rns_id", onupdate="CASCADE"), nullable=True
    )
    is_valid = Column(Boolean, default=True, nullable=False)
    used_at = Column(Integer, nullable=True)
    generated_at = Column(Integer, default=lambda: int(time.time()), nullable=False)

    __table_args__ = (UniqueConstraint(code, inviter, invitee),)

    inviter_member = relationship(
        "Member", back_populates="inviter_codes", foreign_keys=[inviter]
    )
    invitee_member = relationship(
        "Member", back_populates="invitee_codes", foreign_keys=[invitee]
    )

    def to_json(self):
        attributes = {
            c.key: getattr(self, c.key) for c in inspect(self).mapper.column_attrs
        }

        return attributes


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(
        String(40), unique=True, nullable=False, index=True
    )  # stores MAC address
    device_rns_id = Column(String(32), unique=True, nullable=False)

    device_associated_user_id = Column(
        String(32), ForeignKey("members.rns_id", onupdate="CASCADE"), nullable=False
    )
    device_display_name = Column(String(256), nullable=False)

    registered_at = Column(Integer, default=lambda: int(time.time()), nullable=False)
    edited_at = Column(
        Integer,
        default=lambda: int(time.time()),
        onupdate=lambda: int(time.time()),
        nullable=False,
    )

    _type = Column(eum(device_type), nullable=False, default=device_type.user)
    status = Column(
        eum(device_status), nullable=False, default=device_status.registered
    )

    __table_args__ = (
        UniqueConstraint(device_id, device_rns_id, device_associated_user_id),
    )

    member_id = relationship(
        "Member",
        back_populates="user_id_for_device_table",
        foreign_keys=[device_associated_user_id],
        overlaps="devices",
    )
    member = relationship(
        "Member",
        back_populates="devices",
        foreign_keys=[device_associated_user_id],
        overlaps="member_id,user_id_for_device_table",
    )

    def to_json(self):
        attributes = {
            c.key: getattr(self, c.key) for c in inspect(self).mapper.column_attrs
        }
        attributes["_type"] = attributes["_type"].name if attributes["_type"] else None
        attributes["status"] = (
            attributes["status"].name if attributes["status"] else None
        )
        attributes.pop("edited_at", None)
        return attributes

    @staticmethod
    def from_json(data: json, rns_identity):
        _device = Device()
        for key in data.keys():
            _device.__setattr__(key, data.get(key))
        _device.__setattr__("device_associated_user_id", str(rns_identity))

        return _device


class EVM_address(Base):
    __tablename__ = "evm_address"

    id = Column(Integer, primary_key=True, autoincrement=True)

    address = Column(EVMAddress, unique=True, nullable=False, index=True)

    user = Column(
        String(32), ForeignKey("members.rns_id", onupdate="CASCADE"), nullable=False
    )
    usdt_swapped = Column(Numeric(precision=18, scale=4), nullable=False, default="0")

    first_swap_ts = Column(Integer, nullable=True, default=None)

    tx_count = Column(Integer, nullable=False, default=0)

    tx_hash = Column(ARRAY(String), nullable=False, default=["nothing here"])

    @validates(tx_hash)
    def validate_tx_hash(self, key, value):
        if len(value) != len(set(value)):
            raise TimeoutError("Transaction hashes must be unique within the array.")
        return value

    latest_swap_ts = Column(
        Integer,
        default=None,
        onupdate=lambda: int(time.time()),
        nullable=True,
    )

    member_id = relationship(
        "Member",
        back_populates="user_id_for_evm_address",
        foreign_keys=[user],
        overlaps="evm_addresses",
    )
    member = relationship(
        "Member",
        back_populates="evm_addresses",
        foreign_keys=[user],
        overlaps="member_id,user_id_for_evm_address",
    )

    __table_args__ = (UniqueConstraint(address, user),)

    def to_json(self):
        attributes = {
            c.key: (
                float(getattr(self, c.key))
                if c.key == "usdt_swapped"
                else getattr(self, c.key)
            )
            for c in inspect(self).mapper.column_attrs
        }
        return attributes


class faucet_requests(Base):
    __tablename__ = "faucet"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user = Column(
        String(32), ForeignKey("members.rns_id", onupdate="CASCADE"), nullable=False
    )

    address = Column(EVMAddress, unique=True, nullable=False, index=True)

    eth_granted = Column(Numeric(precision=18, scale=0), nullable=False, default=0)

    request_ts = Column(Integer, default=lambda: int(time.time()), nullable=False)

    member_id = relationship(
        "Member", back_populates="user_id_for_faucets", foreign_keys=[user]
    )

    __table_args__ = (UniqueConstraint(address, user),)


class input_token_list_for_ows(Base):
    __tablename__ = "input_token_for_ows"

    id = Column(Integer, primary_key=True, autoincrement=True)

    name = Column(String, nullable=False)

    logo = Column(String, nullable=False)

    address = Column(EVMAddress, nullable=False, unique=True, index=True)

    decimals = Column(Integer, nullable=False, default=18)

    status = Column(eum(token_status), nullable=False, default=token_status.active)

    added_ts = Column(Integer, default=lambda: int(time.time()), nullable=False)

    updated_ts = Column(
        Integer,
        default=lambda: int(time.time()),
        onupdate=lambda: int(time.time()),
        nullable=False,
    )

    __table_args__ = (UniqueConstraint(name, address, logo),)


class swap_vehicles(Base):
    __tablename__ = "swap_vehicles_for_ows"

    id = Column(Integer, primary_key=True, autoincrement=True)

    name = Column(String, nullable=False)

    address = Column(EVMAddress, nullable=False, unique=True, index=True)

    status = Column(eum(token_status), nullable=False, default=token_status.active)

    added_ts = Column(Integer, default=lambda: int(time.time()), nullable=False)

    updated_ts = Column(
        Integer,
        default=lambda: int(time.time()),
        onupdate=lambda: int(time.time()),
        nullable=False,
    )

    __table_args__ = (UniqueConstraint(name, address),)


class whitelisted_contracts(Base):
    __tablename__ = "fwd_whitelist_smart_contracts"

    id = Column(Integer, primary_key=True, autoincrement=True)

    name = Column(String, nullable=False)

    address = Column(EVMAddress, nullable=False, unique=True, index=True)

    status = Column(eum(token_status), nullable=False, default=token_status.active)

    added_ts = Column(Integer, default=lambda: int(time.time()), nullable=False)

    updated_ts = Column(
        Integer,
        default=lambda: int(time.time()),
        onupdate=lambda: int(time.time()),
        nullable=False,
    )

    __table_args__ = (UniqueConstraint(name, address),)


class reward_pools(Base):
    __tablename__ = "fwd_reward_pools"

    id = Column(Integer, primary_key=True, autoincrement=True)

    """string poolName;
        string poolDesc;
        uint256 allocatedSupplyAmount;
        uint256 remainingSupply;
        uint256 rewardAmount;"""

    pool_name = Column(String, nullable=False, unique=True)

    pool_desc = Column(String, nullable=False)

    allocated_supply_amount = Column(Integer, nullable=False, default=0)

    remaining_supply = Column(Integer, nullable=False, default=0)

    reward_amount = Column(Integer, nullable=False, default=0)

    added_ts = Column(Integer, default=lambda: int(time.time()), nullable=False)

    updated_ts = Column(
        Integer,
        default=lambda: int(time.time()),
        onupdate=lambda: int(time.time()),
        nullable=False,
    )


class logs(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, autoincrement=True)

    log_name = Column(String, nullable=False)

    ts = Column(String, nullable=False, default=str(DT.now()))

    message = Column(String, nullable=False)

    status = Column(String, nullable=False)

    remarks = Column(String, nullable=False)


class allocated_tasks(Base):
    __tablename__ = "membership_tasks"

    id = Column(Integer, primary_key=True, autoincrement=True)

    task_id = Column(
        Integer,
        ForeignKey("task_definition.task_id", onupdate="CASCADE"),
        nullable=False,
    )

    member_id = Column(
        String(32), ForeignKey("members.rns_id", onupdate="CASCADE"), nullable=False
    )

    task_issue_ts = Column(Integer, nullable=False)

    task_due_ts = Column(Integer, nullable=False)

    task_completed_ts = Column(Integer, nullable=True)

    refrences = Column(
        String, nullable=True
    )  # this field can hold refrences of invoices, proofs, etc. for the task (can be updated by admin and user)

    user = relationship(
        "Member", back_populates="user_id_for_tasks", foreign_keys=[member_id]
    )

    task = relationship(
        "task_definition", back_populates="definiton_for_tasks", foreign_keys=[task_id]
    )

    __table_args__ = (UniqueConstraint(member_id, task_id),)


class task_definition(Base):
    __tablename__ = "task_definition"

    id = Column(Integer, primary_key=True, autoincrement=True)

    task_id = Column(Integer, nullable=False, unique=True)

    task_title = Column(String, nullable=False)

    task_desc = Column(String, nullable=False)

    task_deadline = Column(Integer, nullable=False, default=0)  # in seconds

    task_defined_ts = Column(Integer, nullable=False, default=int(time.time()))

    fixed_reward = Column(Boolean, nullable=False)

    reward_amount = Column(Float, nullable=True)

    definiton_for_tasks = relationship(
        "allocated_tasks",
        back_populates="task",
        foreign_keys="allocated_tasks.task_id",
    )

    __table_args__ = (
        CheckConstraint(
            "(fixed_reward = TRUE AND reward_amount IS NOT NULL) OR (fixed_reward = FALSE)",
            name="check_fixed_reward_and_reward_amount",
        ),
    )


class Announce(Base):
    __tablename__ = "announces"

    dest = Column(String(32), nullable=False, primary_key=True)
    dest_type = Column(Integer, nullable=False, default=0, primary_key=True)

    data = Column(String, nullable=False, default="")
    data_meta = Column(LargeBinary)

    location_lat = Column(Float, nullable=False, default=0)
    location_lon = Column(Float, nullable=False, default=0)

    owner = Column(String(32), nullable=False, default="")

    state = Column(Integer, nullable=False, default=0)
    state_ts = Column(Integer, nullable=False, default=0)

    hop_count = Column(Integer, nullable=False, default=0)
    hop_interface = Column(String, nullable=False, default="")
    hop_dest = Column(String(32), nullable=False, default="")

    ts_add = Column(Integer, nullable=False, default=0)
    ts_edit = Column(Integer, nullable=False, default=0)


class Service(Base):
    __tablename__ = "services"

    rns_id = Column(String(32), nullable=False, primary_key=True)
    display_name = Column(String(256))

    city = Column(String(100))
    state_name = Column(String(5))
    country = Column(String(2))

    _type = Column(Integer, nullable=False, default=0)
    owner = Column(String(32), ForeignKey("members.rns_id", onupdate="CASCADE"), nullable=False, default="")

    ts_add = Column(Integer, nullable=False, default=0)
    ts_edit = Column(Integer, nullable=False, default=0)

    user = relationship("Member", back_populates="user_id_for_service", foreign_keys=[owner])
