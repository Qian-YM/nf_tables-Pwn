import json
from pwn import *
import sys

micro2val = {}
micro2val['NFTA_SET_ELEM_KEY'] = 1
micro2val['NFTA_SET_ELEM_DATA'] = 2
micro2val['NFTA_DATA_VALUE'] = 1
micro2val['NFTA_DATA_VERDICT'] = 2
micro2val['NFTA_VERDICT_CODE'] = 1
micro2val['NF_DROP'] = 0
micro2val['NONAME'] = 0
micro2val['NFTA_SET_ELEM_LIST_ELEMENTS'] = 3

micro2val['NFTA_HOOK_HOOKNUM'] = 1
micro2val['NFTA_HOOK_PRIORITY'] = 2

micro2val['NFTA_CHAIN_TABLE'] = 1
micro2val['NFTA_CHAIN_NAME'] = 3
micro2val['NFTA_CHAIN_HOOK'] = 4
micro2val['NFTA_CHAIN_FLAGS'] = 10

micro2val['NFPROTO_INET'] = 1 #整个消息体的类型通常就用这个

micro2val['NFTA_RULE_TABLE'] = 1
micro2val['NFTA_RULE_CHAIN'] = 2
micro2val['NFTA_RULE_EXPRESSIONS'] = 4

micro2val['NFTA_LIST_ELEM'] = 1
micro2val['NFTA_EXPR_NAME'] = 1
micro2val['NFTA_HOOK_DEV'] = 3
micro2val['NFTA_CHAIN_TYPE'] = 7
micro2val['NFTA_DUP_SREG_DEV'] = 2
micro2val['NFTA_EXPR_DATA'] = 2
micro2val['NFTA_IMMEDIATE_DREG'] = 1
micro2val['NFTA_IMMEDIATE_DATA'] = 2

micro2val['NFTA_LOOKUP_SET'] = 1
micro2val['NFTA_LOOKUP_SREG'] = 2
micro2val['NFTA_LOOKUP_SET_ID'] = 4

micro2val['NFTA_SET_TABLE'] = 1
micro2val['NFTA_SET_NAME'] = 2
micro2val['NFTA_SET_ID'] = 10
micro2val['NFTA_SET_KEY_LEN'] = 5
micro2val['NFTA_SET_FLAGS'] = 3
micro2val['NFTA_SET_DATA_LEN'] = 7

micro2val['NFTA_SET_FLAGS'] = 3
micro2val['NFT_OBJECT_CT_EXPECT'] = 9
micro2val['NFTA_SET_OBJ_TYPE'] = 15
micro2val['NFTA_SET_DATA_TYPE'] = 6
micro2val['NFTA_SET_FIELD_LEN'] = 1
micro2val['NFTA_SET_DESC_CONCAT'] = 2
micro2val['NFTA_SET_DESC'] = 9

micro2val['NFTA_SET_ELEM_LIST_TABLE'] = 1
micro2val['NFTA_SET_ELEM_LIST_SET'] = 2

micro2val['XFRMA_SEC_CTX'] = 8

micro2val['NFTA_TABLE_NAME'] = 1
micro2val['NFTA_TABLE_FLAGS'] = 2

micro2val['NFTA_SET_ELEM_KEY_END'] = 10
micro2val['NFTA_SET_ELEM_OBJREF'] = 9
micro2val['NFTA_OBJ_TABLE'] = 1
micro2val['NFTA_OBJ_NAME'] = 2
micro2val['NFTA_OBJ_TYPE'] = 3
micro2val['NFTA_OBJ_DATA'] = 4

micro2val['NFTA_TUNNEL_KEY_ID'] = 1
micro2val['NFTA_TUNNEL_KEY_IP'] = 2
micro2val['NFTA_TUNNEL_KEY_OPTS'] = 9

micro2val['NFTA_TUNNEL_KEY_IP_SRC'] = 1
micro2val['NFTA_TUNNEL_KEY_IP_DST'] = 2
micro2val['NFTA_TUNNEL_KEY_GENEVE_CLASS'] = 1
micro2val['NFTA_TUNNEL_KEY_GENEVE_TYPE'] = 2
micro2val['NFTA_TUNNEL_KEY_GENEVE_DATA'] = 3
micro2val['NFTA_TUNNEL_KEY_OPTS_GENEVE'] = 3


class NestAttr:
    def __init__(self):
        pass
    def align(self, length:int)->int:
        res = (length + 3)&(~3)
        return res
    def trans_val(self, val:int)->int:
        code = p32(val)
        rescode = b''
        for c in code:
            rescode = p8(c) + rescode
        res = u32(rescode)
        return res
    def create_nest_attr(self, con:map, mytype:str):
        res = b''
        for contype in con:
            val = con[contype]
            print(contype, type(val))
            contype = contype.split("@")[0]
            print("contype", contype)
            if type(val) == dict:
                subcon, sublen = self.create_nest_attr(val, contype)
                res += subcon
            elif type(val) == int:
                res += p16(8) + p16(micro2val[contype]) + p32(self.trans_val(val))
            elif type(val) == str:
                reallen = len(val)
                newlen = self.align(len(val))
                val = val.ljust(newlen, "\x00")
                res += p16(reallen+4)+p16(micro2val[contype])+val.encode("iso-8859-1")
        nesttype = micro2val[mytype] | 0x8000
        res = p16(len(res)+4) + p16(nesttype) + res  #一个nest_attr的len是data的len
        return res, len(res)
    def create_netlink(self, con:map, family=1):
        res, length = self.create_nest_attr(con, 'NONAME')
        res = p32(family)+res[4:]
        return res, length
def get_nest_attr():
    f = open("./input.json")
    con = json.loads(f.read())
    na = NestAttr()
    res, length = na.create_nest_attr(con, 'NFPROTO_INET')
    print(res)
    if_first = True
    for ch in res:
        if if_first:
            if_first = False
            print(f"{'{'}{ch}", end='')
        else:
            print(f",{ch}", end='')
    print('}')
    print(length)

def get_netlink():
    f = open("./input.json")
    con = json.loads(f.read())
    na = NestAttr()
    res, length = na.create_netlink(con)
    print(res)
    if_first = True
    for ch in res:
        if if_first:
            if_first = False
            print(f"{'{'}{ch}", end='')
        else:
            print(f",{ch}", end='')
    print('}')
    print(length)

if __name__ == '__main__':
    if "--nest" in sys.argv:
        get_nest_attr()
    elif "--netlink" in sys.argv:
        get_netlink()
