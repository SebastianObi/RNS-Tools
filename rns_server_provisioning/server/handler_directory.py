##############################################################################################################
# Include


#### System ####
import time
import uuid
import psycopg2 # TODO: Remove

#### Reticulum ####
# Install: pip3 install rns
# Source: https://markqvist.github.io
import RNS
import RNS.vendor.umsgpack as msgpack

#### Database ####
from sqlalchemy import func, asc, desc
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, OperationalError

#### Internal ####
from utils.utils import RateLimiter, ResponseError
from db.schema import (Device, InviteCode, Member,
                       device_status, device_type, member_role, member_state, sex)


##############################################################################################################
# HandlerDirectory Class


class HandlerDirectory:
    def __init__(self, owner):
        self.owner = owner

        if "limiter_enabled" in self.owner.config["handler_directory"] and  self.owner.config["handler_directory"].getboolean("limiter_enabled"):
            self.limiter = RateLimiter(int(self.owner.config["handler_directory"]["limiter_calls"]), int(self.owner.config["handler_directory"]["limiter_size"]), int(self.owner.config["handler_directory"]["limiter_duration"]))
        else:
            self.limiter = None

        root = self.owner.config["handler_directory"]["root"]

        self.owner.register_request_handler(
            path=root+"directory_announce",
            response_generator=self.announce,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_MSGPACK
        )
        self.owner.register_request_handler(
            path=root+"directory_member",
            response_generator=self.member,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_MSGPACK
        )
        self.owner.register_request_handler(
            path=root+"directory_service",
            response_generator=self.service,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_MSGPACK
        )

        self.db = None
        self.db_load()


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
    # Database                                      #
    #################################################


    def db_connect(self):
        try:
            if self.db == None:
                self.db = psycopg2.connect(user=self.owner.config["database"]["user"], password=self.owner.config["database"]["password"], host=self.owner.config["database"]["host"], port=self.owner.config["database"]["port"], database=self.owner.config["database"]["database"], client_encoding=self.owner.config["database"]["encoding"], connect_timeout=5)
        except:
            self.db = None

        return self.db


    def db_commit(self):
        if self.db != None:
            try:
                self.db.commit()
            except:
                self.db.rollback()


    def db_sanitize(self, value):
        value = str(value)
        value = value.replace('\\', "")
        value = value.replace("\0", "")
        value = value.replace("\n", "")
        value = value.replace("\r", "")
        value = value.replace("'", "")
        value = value.replace('"', "")
        value = value.replace("\x1a", "")
        return value


    def db_init(self, init=True):
        db = self.db_connect()
        dbc = db.cursor()

        self.db_commit()


    def db_migrate(self):
        self.db_init(False)

        db = self.db_connect()
        dbc = db.cursor()

        self.db_commit()

        self.db_init(False)


    def db_indices(self):
        pass


    def db_load(self):
        self.db_init(False)


    #################################################
    # Announce                                      #
    #################################################


    def announce(self, path, data, request_id, link_id, remote_identity, requested_at):
        RNS.log("Server - HandlerDirectory: announce", RNS.LOG_DEBUG)
        RNS.log(data, RNS.LOG_EXTREME)

        if not data:
            return msgpack.packb({self.owner.KEY_RESULT: self.owner.RESULT_NO_DATA})

        dest = RNS.hexrep(RNS.Destination.hash_from_name_and_identity(self.owner.aspect_filter_conv, remote_identity), delimit=False)

        if not self.auth(dest, True):
            return msgpack.packb({self.owner.KEY_RESULT: self.owner.RESULT_NO_RIGHT})

        data_return = {}

        data_return[self.owner.KEY_RESULT] = self.owner.RESULT_OK

        try:
            directory = {}
            entrys = []

            if self.owner.KEY_D_CMD in data:
                if dest in self.owner.admins:
                    cmd = data[self.owner.KEY_D_CMD]
                    if cmd[0] == "delete":
                        self.announce_delete(cmd[1])
                    entry = self.announce_get(cmd[1])
                    if entry:
                        directory.update({self.owner.KEY_D_CMD_RESULT: self.owner.RESULT_OK})
                        entrys = [entry]
                    else:
                        directory.update({self.owner.KEY_D_CMD_RESULT: self.owner.RESULT_OK})
                        entrys = [{"dest": cmd[1]}]
            else:
                directory[self.owner.KEY_D_RX_ENTRYS_COUNT] = self.announce_count(filter=data[self.owner.KEY_D_FILTER], search=data[self.owner.KEY_D_SEARCH], group=data[self.owner.KEY_D_GROUP])
                entrys = self.announce_list(filter=data[self.owner.KEY_D_FILTER], search=data[self.owner.KEY_D_SEARCH], group=data[self.owner.KEY_D_GROUP], order=data[self.owner.KEY_D_ORDER], limit=data[self.owner.KEY_D_LIMIT], limit_start=data[self.owner.KEY_D_LIMIT_START])

            if len(entrys) > 0:
                directory[self.owner.KEY_D_RX_ENTRYS] = []
                entrys_return = []
                for entry in entrys:
                    entry_return = {}
                    for key, value in entry.items():
                        if key in self.owner.KEY_D_ENTRYS_MAPPING:
                            entry_return[self.owner.KEY_D_ENTRYS_MAPPING[key]] = value
                    directory[self.owner.KEY_D_RX_ENTRYS].append(entry_return)

            if dest in self.owner.admins:
                directory[self.owner.KEY_D_CMD] = []
                directory[self.owner.KEY_D_CMD_ENTRY] = ["delete"]

            data_return[self.owner.KEY_D] = directory

        except Exception as e:
            RNS.log("Server - HandlerDirectory: announce", RNS.LOG_ERROR)
            RNS.trace_exception(e)
            data_return[self.owner.KEY_RESULT] = self.owner.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        return data_return


    def announce_filter(self, filter):
        if filter == None:
            return ""

        querys = []

        if "type" in filter and filter["type"] != None:
            if isinstance(filter["type"], int):
                querys.append("dest_type = '"+self.db_sanitize(filter["type"])+"'")
            else:
                array = [self.db_sanitize(key) for key in filter["type"]]
                querys.append("(dest_type = '"+"' OR dest_type = '".join(array)+"')")

        if "hop_min" in filter and filter["hop_min"] != None:
            querys.append("hop_count >= "+self.db_sanitize(filter["hop_min"]))

        if "hop_max" in filter and filter["hop_max"] != None:
            querys.append("hop_count <= "+self.db_sanitize(filter["hop_max"]))

        if "interface" in filter and filter["interface"] != None:
            if isinstance(filter["interface"], str):
                querys.append("hop_interface ILIKE '%"+self.db_sanitize(filter["interface"])+"%'")
            else:
                querys.append("(hop_interface ILIKE '%"+"%' OR hop_interface ILIKE '%".join(filter["interface"])+"%')")

        if "owner" in filter:
            querys.append("owner = '"+self.db_sanitize(RNS.hexrep(filter["owner"], delimit=False))+"'")

        if "state" in filter:
            querys.append("state = '"+self.db_sanitize(filter["state"])+"'")

        if "state_ts_min" in filter and filter["state_ts_min"] != None:
            querys.append("state_ts >= '"+self.db_sanitize(filter["state_ts_min"])+"'")

        if "state_ts_max" in filter and filter["state_ts_max"] != None:
            querys.append("state_ts <= '"+self.db_sanitize(filter["state_ts_max"])+"'")

        if "ts_add_min" in filter and filter["ts_add_min"] != None:
            querys.append("ts_add >= '"+self.db_sanitize(filter["ts_add_min"])+"'")

        if "ts_add_max" in filter and filter["ts_add_max"] != None:
            querys.append("ts_add <= '"+self.db_sanitize(filter["ts_add_max"])+"'")

        if "ts_edit_min" in filter and filter["ts_edit_min"] != None:
            querys.append("ts_edit >= '"+self.db_sanitize(filter["ts_edit_min"])+"'")

        if "ts_edit_max" in filter and filter["ts_edit_max"] != None:
            querys.append("ts_edit <= '"+self.db_sanitize(filter["ts_edit_max"])+"'")

        if "pin" in filter:
            if filter["pin"] == True:
                querys.append("pin = '1'")
            elif filter["pin"] == False:
                querys.append("pin = '0'")

        if "archiv" in filter:
            if filter["archiv"] == True:
                querys.append("archiv = '1'")
            elif filter["archiv"] == False:
                querys.append("archiv = '0'")

        if len(querys) > 0:
            query = " AND "+" AND ".join(querys)
        else:
            query = ""

        return query


    def announce_group(self, group):
        if group == None:
            return ""

        querys = []

        for key in group:
            querys.append(self.db_sanitize(key))

        if len(querys) > 0:
            if key == "type": key = "dest_type"
            query = " GROUP BY "+", ".join(querys)
        else:
            query = ""

        return query


    def announce_order(self, order):
        if order == "A-ASC":
            query = " ORDER BY data ASC"
        elif order == "A-DESC":
            query = " ORDER BY data DESC"
        elif order == "T-ASC":
            query = " ORDER BY dest_type ASC, ts_edit ASC, data ASC"
        elif order == "T-DESC":
            query = " ORDER BY dest_type DESC, ts_edit ASC, data ASC"
        elif order == "H-ASC":
            query = " ORDER BY hop_count ASC, ts_edit ASC, data ASC"
        elif order == "H-DESC":
            query = " ORDER BY hop_count DESC, ts_edit ASC, data ASC"
        elif order == "I-ASC":
            query = " ORDER BY hop_interface ASC, ts_edit ASC, data ASC"
        elif order == "I-DESC":
            query = " ORDER BY hop_interface DESC, ts_edit ASC, data ASC"
        elif order == "S-ASC":
            query = " ORDER BY state_ts ASC, data ASC"
        elif order == "S-DESC":
            query = " ORDER BY state_ts DESC, data ASC"
        elif order == "TSA-ASC":
            query = " ORDER BY ts_add ASC, data ASC"
        elif order == "TSA-DESC":
            query = " ORDER BY ts_add DESC, data ASC"
        elif order == "TSE-ASC":
            query = " ORDER BY ts_edit ASC, data ASC"
        elif order == "TSE-DESC":
            query = " ORDER BY ts_edit DESC, data ASC"
        else:
            query = ""

        return query


    def announce_list(self, filter=None, search=None, group=None, order=None, limit=None, limit_start=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.announce_filter(filter)

        query_group = self.announce_group(group)

        query_order = self.announce_order(order)

        if limit == None or limit_start == None:
            query_limit = ""
        else:
            query_limit = " LIMIT "+self.db_sanitize(limit)+" OFFSET "+self.db_sanitize(limit_start)

        if search:
            search = "%"+search+"%"
            query = "SELECT * FROM announces WHERE dest_type >= 0 AND data ILIKE %s"+query_filter+query_group+query_order+query_limit
            dbc.execute(query, (search,))
        else:
            query = "SELECT * FROM announces WHERE dest_type >= 0"+query_filter+query_group+query_order+query_limit
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return []
        else:
            data = []
            for entry in result:
                owner = entry[6].strip()
                owner = bytes.fromhex(owner) if owner else None
                data.append({
                    "dest": bytes.fromhex(entry[0].strip()),
                    "type": entry[1],
                    "data": entry[2].strip(),
                    "location_lat": entry[4],
                    "location_lon": entry[5],
                    "owner": owner,
                    "state": entry[7],
                    "state_ts": entry[8],
                    "hop_count": entry[9],
                    "ts_add": entry[12],
                    "ts_edit": entry[13],
                })

            return data


    def announce_count(self, filter=None, search=None, group=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.announce_filter(filter)

        query_group = self.announce_group(group)

        if search:
            search = "%"+search+"%"
            query = "SELECT COUNT(*) FROM announces WHERE dest_type >= 0 AND data ILIKE %s"+query_filter+query_group
            dbc.execute(query, (search,))
        else:
            query = "SELECT COUNT(*) FROM announces WHERE dest_type >= 0"+query_filter+query_group
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def announce_get(self, dest):
        db = self.db_connect()
        dbc = db.cursor()

        query = "SELECT * FROM announces WHERE dest = %s"
        dbc.execute(query, (RNS.hexrep(dest, False),))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            entry = result[0]
            owner = entry[6].strip()
            owner = bytes.fromhex(owner) if owner else None
            data = {
                "dest": bytes.fromhex(entry[0].strip()),
                "type": entry[1],
                "data": entry[2].strip(),
                "location_lat": entry[4],
                "location_lon": entry[5],
                "owner": owner,
                "state": entry[7],
                "state_ts": entry[8],
                "hop_count": entry[9],
                "ts_add": entry[12],
                "ts_edit": entry[13],
            }
            return data


    def announce_delete(self, dest):
        try:
            db = self.db_connect()
            dbc = db.cursor()

            query = "DELETE FROM announces WHERE dest = %s"
            dbc.execute(query, (RNS.hexrep(dest, False),))

            self.db_commit()

        except psycopg2.DatabaseError as e:
            db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, None, "DB - Error: "+str(e))


    #################################################
    # Member                                        #
    #################################################


    def member(self, path, data, request_id, link_id, remote_identity, requested_at):
        RNS.log("Server - HandlerDirectory: member", RNS.LOG_DEBUG)
        RNS.log(data, RNS.LOG_EXTREME)

        if not data:
            return msgpack.packb({self.owner.KEY_RESULT: self.owner.RESULT_NO_DATA})

        dest = RNS.hexrep(RNS.Destination.hash_from_name_and_identity(self.owner.aspect_filter_conv, remote_identity), delimit=False)

        if not self.auth(dest, True):
            return msgpack.packb({self.owner.KEY_RESULT: self.owner.RESULT_NO_RIGHT})

        data_return = {}

        data_return[self.owner.KEY_RESULT] = self.owner.RESULT_OK

        try:
            directory = {}
            entrys = []
            group_entrys = []

            if self.owner.KEY_D_CMD in data:
                if dest in self.owner.admins:
                    cmd = data[self.owner.KEY_D_CMD]
                    if cmd[0] == "role_0":
                        self.member_set(cmd[1], role=0)
                    if cmd[0] == "role_1":
                        self.member_set(cmd[1], role=1)
                    if cmd[0] == "role_2":
                        self.member_set(cmd[1], role=2)
                    if cmd[0] == "role_3":
                        self.member_set(cmd[1], role=3)
                    if cmd[0] == "state_0":
                        self.member_set(cmd[1], state=0)
                    if cmd[0] == "state_1":
                        self.member_set(cmd[1], state=1)
                    if cmd[0] == "state_2":
                        self.member_set(cmd[1], state=2)
                    if cmd[0] == "delete":
                        self.member_delete(cmd[1])
                    entry = self.member_get(cmd[1])
                    if entry:
                        directory.update({self.owner.KEY_D_CMD_RESULT: self.owner.RESULT_OK})
                        entrys = [entry]
                    else:
                        directory.update({self.owner.KEY_D_CMD_RESULT: self.owner.RESULT_OK})
                        entrys = [{"dest": cmd[1]}]
            elif self.owner.KEY_D_GROUP in data and data[self.owner.KEY_D_GROUP] != None:
                group_entrys = self.member_count_list(filter=data[self.owner.KEY_D_FILTER], search=data[self.owner.KEY_D_SEARCH], group=data[self.owner.KEY_D_GROUP], order=data[self.owner.KEY_D_ORDER], limit=data[self.owner.KEY_D_LIMIT], limit_start=data[self.owner.KEY_D_LIMIT_START])
                directory[self.owner.KEY_D_RX_GROUP_ENTRYS_COUNT] = len(group_entrys)
            else:
                directory[self.owner.KEY_D_RX_ENTRYS_COUNT] = self.member_count(filter=data[self.owner.KEY_D_FILTER], search=data[self.owner.KEY_D_SEARCH], group=data[self.owner.KEY_D_GROUP])

                for entry in self.member_list(filter=data[self.owner.KEY_D_FILTER], search=data[self.owner.KEY_D_SEARCH], group=data[self.owner.KEY_D_GROUP], order=data[self.owner.KEY_D_ORDER], limit=data[self.owner.KEY_D_LIMIT], limit_start=data[self.owner.KEY_D_LIMIT_START]):
                    if entry["dest"] in data[self.owner.KEY_D_ENTRYS]:
                        if entry["ts_edit"] > data[self.owner.KEY_D_ENTRYS][entry["dest"]]:
                            entrys.append(entry)
                        del data[self.owner.KEY_D_ENTRYS][entry["dest"]]
                    else:
                        entrys.append(entry)

                for dest in data[self.owner.KEY_D_ENTRYS]:
                    entry = self.member_get(dest=dest)
                    if entry:
                        if entry["ts_edit"] > data[self.owner.KEY_D_ENTRYS][dest]:
                            entrys.append(entry)
                    else:
                        entrys.append({"dest": dest})

            if len(entrys) > 0:
                directory[self.owner.KEY_D_RX_ENTRYS] = []
                entrys_return = []
                for entry in entrys:
                    entry_return = {}
                    for key, value in entry.items():
                        if key in self.owner.KEY_D_ENTRYS_MAPPING:
                            entry_return[self.owner.KEY_D_ENTRYS_MAPPING[key]] = value
                    directory[self.owner.KEY_D_RX_ENTRYS].append(entry_return)

            if len(group_entrys) > 0:
                directory[self.owner.KEY_D_RX_GROUP_ENTRYS] = []
                entrys_return = []
                for entry in group_entrys:
                    entry_return = {}
                    for key, value in entry.items():
                        if key in self.owner.KEY_D_ENTRYS_MAPPING:
                            entry_return[self.owner.KEY_D_ENTRYS_MAPPING[key]] = value
                    directory[self.owner.KEY_D_RX_GROUP_ENTRYS].append(entry_return)

            if dest in self.owner.admins:
                directory[self.owner.KEY_D_CMD] = []
                directory[self.owner.KEY_D_CMD_ENTRY] = ["role_0", "role_1", "role_2", "role_3", "state_0", "state_1", "state_2", "delete"]

            data_return[self.owner.KEY_D] = directory

        except Exception as e:
            RNS.log("Server - HandlerDirectory: member", RNS.LOG_ERROR)
            RNS.trace_exception(e)
            data_return[self.owner.KEY_RESULT] = self.owner.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        return data_return


    def member_filter(self, filter):
        if filter == None:
            return ""

        querys = []

        if "display_name" in filter and filter["display_name"] != None:
            querys.append("display_name ILIKE '%"+self.db_sanitize(filter["display_name"])+"%'")

        if "city" in filter and filter["city"] != None:
            querys.append("city ILIKE '%"+self.db_sanitize(filter["city"])+"%'")

        if "country" in filter and filter["country"] != None:
            querys.append("country = '"+self.db_sanitize(filter["country"])+"'")

        if "state" in filter and filter["state"] != None:
            querys.append("state_name = '"+self.db_sanitize(filter["state"])+"'")

        if "occupation" in filter and filter["occupation"] != None:
            querys.append("occupation ILIKE '%"+self.db_sanitize(filter["occupation"])+"%'")

        if "skills" in filter and filter["skills"] != None:
            querys.append("skills ILIKE '%"+self.db_sanitize(filter["skills"])+"%'")

        if "shop_goods" in filter and filter["shop_goods"] != None:
            querys.append("shop_goods ILIKE '%"+self.db_sanitize(filter["shop_goods"])+"%'")

        if "shop_services" in filter and filter["shop_services"] != None:
            querys.append("shop_services ILIKE '%"+self.db_sanitize(filter["shop_services"])+"%'")

        if "auth_role" in filter and filter["auth_role"] != None:
            querys.append("role = '"+self.db_sanitize(member_role(filter["auth_role"]).name)+"'")

        if "ts_add_min" in filter and filter["ts_add_min"] != None:
            querys.append("registered_at >= '"+self.db_sanitize(filter["ts_add_min"])+"'")

        if "ts_add_max" in filter and filter["ts_add_max"] != None:
            querys.append("registered_at <= '"+self.db_sanitize(filter["ts_add_max"])+"'")

        if "ts_edit_min" in filter and filter["ts_edit_min"] != None:
            querys.append("edited_at >= '"+self.db_sanitize(filter["ts_edit_min"])+"'")

        if "ts_edit_max" in filter and filter["ts_edit_max"] != None:
            querys.append("edited_at <= '"+self.db_sanitize(filter["ts_add_min"])+"'")

        if len(querys) > 0:
            query = " AND "+" AND ".join(querys)
        else:
            query = ""

        return query


    def member_group(self, group):
        if group == None:
            return ""

        querys = []

        for key in group:
            if key == "state": key = "state_name"
            if key.startswith("auth_"): key = key.replace("auth_", "")
            querys.append(self.db_sanitize(key))

        if len(querys) > 0:
            query = " GROUP BY "+", ".join(querys)
        else:
            query = ""

        return query


    def member_order(self, order):
        if order == "A-ASC":
            query = " ORDER BY display_name ASC"
        elif order == "A-DESC":
            query = " ORDER BY display_name DESC"
        elif order == "R-ASC":
            query = " ORDER BY role ASC, display_name ASC"
        elif order == "R-DESC":
            query = " ORDER BY role DESC, display_name ASC"
        elif order == "C-ASC":
            query = " ORDER BY country ASC, display_name ASC"
        elif order == "C-DESC":
            query = " ORDER BY country DESC, display_name ASC"
        elif order == "S-ASC":
            query = " ORDER BY country ASC, state_name ASC, display_name ASC"
        elif order == "S-DESC":
            query = " ORDER BY country DESC, state_name DESC, display_name ASC"
        elif order == "CITY-ASC":
            query = " ORDER BY country ASC, city ASC, display_name ASC"
        elif order == "CITY-DESC":
            query = " ORDER BY country DESC, city DESC, display_name ASC"
        elif order == "TSA-ASC":
            query = " ORDER BY registered_at ASC, display_name ASC"
        elif order == "TSA-DESC":
            query = " ORDER BY registered_at DESC, display_name ASC"
        elif order == "TSE-ASC":
            query = " ORDER BY edited_at ASC, display_name ASC"
        elif order == "TSE-DESC":
            query = " ORDER BY edited_at DESC, display_name ASC"
        else:
            query = ""

        return query


    def member_list(self, filter=None, search=None, group=None, order=None, limit=None, limit_start=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.member_filter(filter)

        query_group = self.member_group(group)

        query_order = self.member_order(order)

        if limit == None or limit_start == None:
            query_limit = ""
        else:
            query_limit = " LIMIT "+self.db_sanitize(limit)+" OFFSET "+self.db_sanitize(limit_start)

        if search:
            search = "%"+search+"%"
            query = "SELECT rns_id, display_name, city, state_name, country, occupation, skills, shop_goods, shop_services, role, registered_at, edited_at FROM members WHERE rns_id != '' AND (display_name ILIKE %s OR city ILIKE %s OR occupation ILIKE %s OR skills ILIKE %s OR shop_goods ILIKE %s OR shop_services ILIKE %s)"+query_filter+query_group+query_order+query_limit
            dbc.execute(query, (search, search, search, search, search, search))
        else:
            query = "SELECT rns_id, display_name, city, state_name, country, occupation, skills, shop_goods, shop_services, role, registered_at, edited_at FROM members WHERE rns_id != ''"+query_filter+query_group+query_order+query_limit
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return []
        else:
            data = []
            for entry in result:
                if entry[10]:
                    data.append({
                        "dest": bytes.fromhex(entry[0].strip()),
                        "display_name": entry[1].strip(),
                        "city": entry[2].strip(),
                        "state": entry[3].strip(),
                        "country": entry[4].strip(),
                        "occupation": entry[5].strip(),
                        "skills": entry[6].strip(),
                        "shop_goods": entry[7].strip(),
                        "shop_services": entry[8].strip(),
                        "auth_role": member_role[entry[9]].value,
                        "ts_add": entry[10],
                        "ts_edit": entry[11],
                    })
            return data


    def member_count(self, filter=None, search=None, group=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.member_filter(filter)

        query_group = self.member_group(group)

        if search:
            search = "%"+search+"%"
            query = "SELECT COUNT(*) FROM members WHERE rns_id != '' AND (display_name ILIKE %s OR city ILIKE %s OR occupation ILIKE %s OR skills ILIKE %s OR shop_goods ILIKE %s OR shop_services ILIKE %s)"+query_filter+query_group
            dbc.execute(query, (search, search, search, search, search, search))
        else:
            query = "SELECT COUNT(*) FROM members WHERE rns_id != ''"+query_filter+query_group
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def member_count_list(self, filter=None, search=None, group=None, order=None, limit=None, limit_start=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.member_filter(filter)

        query_group = self.member_group(group)

        query_order = self.member_order(order)
        query_order = query_order.replace(" ORDER BY display_name ASC", "")
        query_order = query_order.replace(" ORDER BY display_name DESC", "")
        query_order = query_order.replace(", display_name ASC", "")

        if limit == None or limit_start == None:
            query_limit = ""
        else:
            query_limit = " LIMIT "+self.db_sanitize(limit)+" OFFSET "+self.db_sanitize(limit_start)

        if search:
            search = "%"+search+"%"
            query = "SELECT COUNT(registered_at), MAX(country), MAX(state_name), MAX(city), MAX(role) FROM members WHERE rns_id != '' AND (display_name ILIKE %s OR city ILIKE %s OR occupation ILIKE %s OR skills ILIKE %s OR shop_goods ILIKE %s OR shop_services ILIKE %s)"+query_filter+query_group+query_order+query_limit
            dbc.execute(query, (search, search, search, search, search, search))
        else:
            query = "SELECT COUNT(registered_at), MAX(country), MAX(state_name), MAX(city), MAX(role) FROM members WHERE rns_id != ''"+query_filter+query_group+query_order+query_limit
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return []
        else:
            data = []
            for entry in result:
                data.append({
                    "count": entry[0],
                    "country": entry[1].strip(),
                    "state": entry[2].strip(),
                    "city": entry[3].strip(),
                    "auth_role": member_role[entry[4]].value
                })
            return data


    def member_get(self, dest):
        db = self.db_connect()
        dbc = db.cursor()

        query = "SELECT rns_id, display_name, city, state_name, country, occupation, skills, shop_goods, shop_services, role, registered_at, edited_at FROM members WHERE rns_id = %s"
        dbc.execute(query, (RNS.hexrep(dest, False),))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            entry = result[0]
            data = {
                "dest": bytes.fromhex(entry[0].strip()),
                "display_name": entry[1].strip(),
                "city": entry[2].strip(),
                "state": entry[3].strip(),
                "country": entry[4].strip(),
                "occupation": entry[5].strip(),
                "skills": entry[6].strip(),
                "shop_goods": entry[7].strip(),
                "shop_services": entry[8].strip(),
                "auth_role": member_role[entry[9]].value,
                "ts_add": entry[10],
                "ts_edit": entry[11],
            }
            return data


    def member_set(self, dest, role=None, state=None):
        try:
            db = self.db_connect()
            dbc = db.cursor()

            if role != None:
                query = "UPDATE members SET edited_at = %s, role = %s WHERE rns_id = %s"
                dbc.execute(query, (int(time.time()), member_role(role).name, RNS.hexrep(dest, False)))

            if state != None:
                query = "UPDATE members SET edited_at = %s, state = %s WHERE rns_id = %s)"
                dbc.execute(query, (int(time.time()), member_state(state).name, RNS.hexrep(dest, False)))

            self.db_commit()

        except psycopg2.DatabaseError as e:
            db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, None, "DB - Error: "+str(e))


    def member_delete(self, dest):
        try:
            db = self.db_connect()
            dbc = db.cursor()

            # Member
            query = "DELETE FROM members WHERE rns_id = %s"
            dbc.execute(query, (RNS.hexrep(dest, False),))

            # Device
            query = "DELETE FROM devices WHERE device_associated_user_id = %s"
            dbc.execute(query, (RNS.hexrep(dest, False),))

            self.db_commit()

        except psycopg2.DatabaseError as e:
            db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, None, "DB - Error: "+str(e))


    #################################################
    # Service                                       #
    #################################################


    def service(self, path, data, request_id, link_id, remote_identity, requested_at):
        RNS.log("Server - HandlerDirectory: service", RNS.LOG_DEBUG)
        RNS.log(data, RNS.LOG_EXTREME)

        if not data:
            return msgpack.packb({self.owner.KEY_RESULT: self.owner.RESULT_NO_DATA})

        dest = RNS.hexrep(RNS.Destination.hash_from_name_and_identity(self.owner.aspect_filter_conv, remote_identity), delimit=False)

        if not self.auth(dest, True):
            return msgpack.packb({self.owner.KEY_RESULT: self.owner.RESULT_NO_RIGHT})

        data_return = {}

        data_return[self.owner.KEY_RESULT] = self.owner.RESULT_OK

        try:
            directory = {}
            entrys = []
            group_entrys = []

            if self.owner.KEY_D_CMD in data:
                if dest in self.owner.admins:
                    cmd = data[self.owner.KEY_D_CMD]
                    if cmd[0] == "delete":
                        self.service_delete(cmd[1])
                    entry = self.service_get(cmd[1])
                    if entry:
                        directory.update({self.owner.KEY_D_CMD_RESULT: self.owner.RESULT_OK})
                        entrys = [entry]
                    else:
                        directory.update({self.owner.KEY_D_CMD_RESULT: self.owner.RESULT_OK})
                        entrys = [{"dest": cmd[1]}]
            elif self.owner.KEY_D_GROUP in data and data[self.owner.KEY_D_GROUP] != None:
                group_entrys = self.service_count_list(filter=data[self.owner.KEY_D_FILTER], search=data[self.owner.KEY_D_SEARCH], group=data[self.owner.KEY_D_GROUP], order=data[self.owner.KEY_D_ORDER], limit=data[self.owner.KEY_D_LIMIT], limit_start=data[self.owner.KEY_D_LIMIT_START])
                directory[self.owner.KEY_D_RX_GROUP_ENTRYS_COUNT] = len(group_entrys)
            else:
                directory[self.owner.KEY_D_RX_ENTRYS_COUNT] = self.service_count(filter=data[self.owner.KEY_D_FILTER], search=data[self.owner.KEY_D_SEARCH], group=data[self.owner.KEY_D_GROUP])

                for entry in self.service_list(filter=data[self.owner.KEY_D_FILTER], search=data[self.owner.KEY_D_SEARCH], group=data[self.owner.KEY_D_GROUP], order=data[self.owner.KEY_D_ORDER], limit=data[self.owner.KEY_D_LIMIT], limit_start=data[self.owner.KEY_D_LIMIT_START]):
                    if entry["dest"] in data[self.owner.KEY_D_ENTRYS]:
                        if entry["ts_edit"] > data[self.owner.KEY_D_ENTRYS][entry["dest"]]:
                            entrys.append(entry)
                        del data[self.owner.KEY_D_ENTRYS][entry["dest"]]
                    else:
                        entrys.append(entry)

                for dest in data[self.owner.KEY_D_ENTRYS]:
                    entry = self.service_get(dest=dest)
                    if entry:
                        if entry["ts_edit"] > data[self.owner.KEY_D_ENTRYS][dest]:
                            entrys.append(entry)
                    else:
                        entrys.append({"dest": dest})

            if len(entrys) > 0:
                directory[self.owner.KEY_D_RX_ENTRYS] = []
                entrys_return = []
                for entry in entrys:
                    entry_return = {}
                    for key, value in entry.items():
                        if key in self.owner.KEY_D_ENTRYS_MAPPING:
                            entry_return[self.owner.KEY_D_ENTRYS_MAPPING[key]] = value
                    directory[self.owner.KEY_D_RX_ENTRYS].append(entry_return)

            if len(group_entrys) > 0:
                directory[self.owner.KEY_D_RX_GROUP_ENTRYS] = []
                entrys_return = []
                for entry in group_entrys:
                    entry_return = {}
                    for key, value in entry.items():
                        if key in self.owner.KEY_D_ENTRYS_MAPPING:
                            entry_return[self.owner.KEY_D_ENTRYS_MAPPING[key]] = value
                    directory[self.owner.KEY_D_RX_GROUP_ENTRYS].append(entry_return)

            if dest in self.owner.admins:
                directory[self.owner.KEY_D_CMD] = []
                directory[self.owner.KEY_D_CMD_ENTRY] = []

            data_return[self.owner.KEY_D] = directory

        except Exception as e:
            RNS.log("Server - HandlerDirectory: service", RNS.LOG_ERROR)
            RNS.trace_exception(e)
            data_return[self.owner.KEY_RESULT] = self.owner.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        return data_return


    def service_filter(self, filter):
        if filter == None:
            return ""

        querys = []

        if "display_name" in filter and filter["display_name"] != None:
            querys.append("display_name ILIKE '%"+self.db_sanitize(filter["display_name"])+"%'")

        if "city" in filter and filter["city"] != None:
            querys.append("city ILIKE '%"+self.db_sanitize(filter["city"])+"%'")

        if "country" in filter and filter["country"] != None:
            querys.append("country = '"+self.db_sanitize(filter["country"])+"'")

        if "state" in filter and filter["state"] != None:
            querys.append("state_name = '"+self.db_sanitize(filter["state"])+"'")

        if "type" in filter and filter["type"] != None:
            if isinstance(filter["type"], int):
                querys.append("_type = '"+self.db_sanitize(filter["type"])+"'")
            else:
                array = [self.db_sanitize(key) for key in filter["type"]]
                querys.append("(_type = '"+"' OR _type = '".join(array)+"')")

        if "owner" in filter:
            querys.append("owner = '"+self.db_sanitize(RNS.hexrep(filter["owner"], delimit=False))+"'")

        if "auth_role" in filter and filter["auth_role"] != None:
            querys.append("role = '"+self.db_sanitize(member_role(filter["auth_role"])).name+"'")

        if "ts_add_min" in filter and filter["ts_add_min"] != None:
            querys.append("ts_add >= '"+self.db_sanitize(filter["ts_add_min"])+"'")

        if "ts_add_max" in filter and filter["ts_add_max"] != None:
            querys.append("ts_add <= '"+self.db_sanitize(filter["ts_add_max"])+"'")

        if "ts_edit_min" in filter and filter["ts_edit_min"] != None:
            querys.append("ts_edit >= '"+self.db_sanitize(filter["ts_edit_min"])+"'")

        if "ts_edit_max" in filter and filter["ts_edit_max"] != None:
            querys.append("ts_edit <= '"+self.db_sanitize(filter["ts_edit_max"])+"'")

        if len(querys) > 0:
            query = " AND "+" AND ".join(querys)
        else:
            query = ""

        return query


    def service_group(self, group):
        if group == None:
            return ""

        querys = []

        for key in group:
            if key == "state": key = "state_name"
            if key == "type": key = "_type"
            if key.startswith("auth_"): key = key.replace("auth_", "")
            if key == "role":
                continue
            querys.append(self.db_sanitize(key))

        if len(querys) > 0:
            query = " GROUP BY "+", ".join(querys)
        else:
            query = ""

        return query


    def service_order(self, order):
        if order == "A-ASC":
            query = " ORDER BY display_name ASC"
        elif order == "A-DESC":
            query = " ORDER BY display_name DESC"
        #elif order == "R-ASC":
        #    query = " ORDER BY role ASC, display_name ASC"
        #elif order == "R-DESC":
        #    query = " ORDER BY role DESC, display_name ASC"
        elif order == "C-ASC":
            query = " ORDER BY country ASC, display_name ASC"
        elif order == "C-DESC":
            query = " ORDER BY country DESC, display_name ASC"
        elif order == "S-ASC":
            query = " ORDER BY country ASC, state_name ASC, display_name ASC"
        elif order == "S-DESC":
            query = " ORDER BY country DESC, state_name DESC, display_name ASC"
        elif order == "CITY-ASC":
            query = " ORDER BY country ASC, city ASC, display_name ASC"
        elif order == "CITY-DESC":
            query = " ORDER BY country DESC, city DESC, display_name ASC"
        elif order == "TSA-ASC":
            query = " ORDER BY ts_add ASC, display_name ASC"
        elif order == "TSA-DESC":
            query = " ORDER BY ts_add DESC, display_name ASC"
        elif order == "TSE-ASC":
            query = " ORDER BY ts_edit ASC, display_name ASC"
        elif order == "TSE-DESC":
            query = " ORDER BY ts_edit DESC, display_name ASC"
        else:
            query = ""

        return query


    def service_list(self, filter=None, search=None, group=None, order=None, limit=None, limit_start=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.service_filter(filter)

        query_group = self.service_group(group)

        query_order = self.service_order(order)

        if limit == None or limit_start == None:
            query_limit = ""
        else:
            query_limit = " LIMIT "+self.db_sanitize(limit)+" OFFSET "+self.db_sanitize(limit_start)

        if search:
            search = "%"+search+"%"
            query = "SELECT rns_id, display_name, country, state_name, city, _type, owner, ts_add, ts_edit FROM services WHERE rns_id != '' AND (display_name ILIKE %s OR city ILIKE %s)"+query_filter+query_group+query_order+query_limit
            dbc.execute(query, (search, search))
        else:
            query = "SELECT rns_id, display_name, country, state_name, city, _type, owner, ts_add, ts_edit FROM services WHERE rns_id != ''"+query_filter+query_group+query_order+query_limit
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return []
        else:
            data = []
            for entry in result:
                owner = entry[6].strip()
                owner = bytes.fromhex(owner) if owner else None
                data.append({
                    "dest": bytes.fromhex(entry[0].strip()),
                    "display_name": entry[1].strip(),
                    "country": entry[2].strip(),
                    "state": entry[3].strip(),
                    "city": entry[4].strip(),
                    "type": entry[5],
                    "owner": owner,
                    "auth_role": 0,
                    "ts_add": entry[7],
                    "ts_edit": entry[8],
                })

            return data


    def service_count(self, filter=None, search=None, group=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.service_filter(filter)

        query_group = self.service_group(group)

        if search:
            search = "%"+search+"%"
            query = "SELECT COUNT(*) FROM services WHERE rns_id != '' AND (display_name ILIKE %s OR city ILIKE %s)"+query_filter+query_group
            dbc.execute(query, (search, search))
        else:
            query = "SELECT COUNT(*) FROM services WHERE rns_id != ''"+query_filter+query_group
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def service_count_list(self, filter=None, search=None, group=None, order=None, limit=None, limit_start=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.service_filter(filter)

        query_group = self.service_group(group)

        query_order = self.service_order(order)
        query_order = query_order.replace(" ORDER BY display_name ASC", "")
        query_order = query_order.replace(" ORDER BY display_name DESC", "")
        query_order = query_order.replace(", display_name ASC", "")

        if limit == None or limit_start == None:
            query_limit = ""
        else:
            query_limit = " LIMIT "+self.db_sanitize(limit)+" OFFSET "+self.db_sanitize(limit_start)

        if search:
            search = "%"+search+"%"
            query = "SELECT COUNT(ts_add), MAX(country), MAX(state_name), MAX(city) FROM services WHERE rns_id != '' AND (display_name ILIKE %s OR city ILIKE %s)"+query_filter+query_group+query_order+query_limit
            dbc.execute(query, (search, search))
        else:
            query = "SELECT COUNT(ts_add), MAX(country), MAX(state_name), MAX(city) FROM services WHERE rns_id != ''"+query_filter+query_group+query_order+query_limit
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return []
        else:
            data = []
            for entry in result:
                data.append({
                    "count": entry[0],
                    "country": entry[1].strip(),
                    "state": entry[2].strip(),
                    "city": entry[3].strip(),
                    "auth_role": 0
                })
            return data


    def service_get(self, dest):
        db = self.db_connect()
        dbc = db.cursor()

        query = "SELECT rns_id, display_name, country, state_name, city, _type, owner, ts_add, ts_edit FROM services WHERE rns_id = %s"
        dbc.execute(query, (RNS.hexrep(dest, False),))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            entry = result[0]
            owner = entry[6].strip()
            owner = bytes.fromhex(owner) if owner else None
            data = {
                "dest": bytes.fromhex(entry[0].strip()),
                "display_name": entry[1].strip(),
                "country": entry[2].strip(),
                "state": entry[3].strip(),
                "city": entry[4].strip(),
                "type": entry[5].strip(),
                "owner": owner,
                "auth_role": 0,
                "ts_add": entry[8],
                "ts_edit": entry[9],
            }
            return data


    def service_delete(self, dest):
        try:
            db = self.db_connect()
            dbc = db.cursor()

            query = "DELETE FROM services WHERE rns_id = %s"
            dbc.execute(query, (RNS.hexrep(dest, False),))

            self.db_commit()

        except psycopg2.DatabaseError as e:
            db.rollback()
            raise ResponseError(self.owner.TRANSACTION_STATE_FAILED_TMP, None, "DB - Error: "+str(e))
