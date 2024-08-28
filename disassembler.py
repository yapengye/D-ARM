# This file is part of D-ARM
# Copyright (C) 2023 Yapeng Ye, yapengye@gmail.com

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>

import copy
import gc
import heapq
import logging
import os
import struct
from collections import defaultdict

from binary import ARMBinary
from capstone import *
from capstone.arm import *
from capstone.arm64 import *


class NodeInst:
    def __init__(self, inst=None):
        self.inst = inst
        self.type = None  # A/T
        self.size = 0
        # self.succr1 = -1
        # self.succr2 = -1
        self.succr = list()
        self.succr_data = list()
        self.pred = list()
        self.hint = 0


class NodeData:
    def __init__(self):
        self.type = 0  # default: 0 data; 1 unknown/inst #TODO check: now used for counting overlapped insts
        self.accessed_inst = list()
        self.hint = 0


class ARMDisassembler:
    S_UNCOMMON_OP = -1
    S_LIKE_DATA = -1
    S_REG_REDEFINE = -10
    S_CLOSE_TARGET = -10
    S_COMMON_BASIC = 5
    S_MOVW_MOVT = 10
    S_CMP_CC = 1

    HT_CF_CONVERGE = 1.0 / 65535.0
    HT_CF_CROSS = 1.0 / 65535.0
    HT_REG = 1.0 / 2  # 1.0 / 16.0
    T_LSTM_DATA_MIN = 0.02  ## TODO: update
    T_LSTM_DATA_AVE = 0.2

    ADDR_SUCCR_VALID = 0.1
    ADDR_SUCCR_PERFECT = 0.5
    ADDR_DATA_VALID = 0.1
    ADDR_DATA_PERFECT = 0.5

    # TODO: use const from capstone
    COMMON_INST_ID_32 = set(
        [
            75,
            82,
            2,
            214,
            17,
            215,
            413,
            23,
            13,
            62,
            205,
            412,
            93,
            8,
            423,
            414,
            424,
            408,
            15,
            1,
            225,
            34,
            425,
            117,
            68,
            14,
            11,
            211,
            92,
            22,
            227,
            122,
            91,
            417,
            84,
            83,
            21,
            173,
            202,
            416,
            241,
            422,
            421,
            70,
            242,
            3,
            259,
            222,
            261,
            206,
            407,
            418,
            59,
            80,
            231,
            63,
            81,
            203,
            60,
            97,
            10,
        ]
    )

    def __init__(self, filepath_binary, aarch=None, output_dir=None, verbose=False):
        self.filepath_binary = filepath_binary
        self.output_dir = output_dir
        self.aarch = aarch
        self.verbose = verbose

        self.binary = ARMBinary(self.filepath_binary, aarch=self.aarch)
        self.aarch = self.binary.aarch

        self.sections = dict()
        # address: [h, size, successor1, successor2, predecessors, inst]
        self.superset = dict()
        self.data = dict()

        self.aggregated_scores = dict()
        # addr: h, cf_convergence, cf_crossing, register def-use
        self.hint_scores = dict()
        # addr: data, arm, thumb
        self.hint_dl = dict()

        self.convert_capstone_const()
        self.get_sectioninfo()

        if self.output_dir:
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
            self.filepath_hint_analysis = os.path.join(
                self.output_dir, "h_analysis.txt"
            )

    def convert_capstone_const(self):
        # TODO: put const in separate files
        if self.aarch == 32:
            self.ARM_INS_NOP = ARM_INS_NOP
            self.ARM_INS_POP = ARM_INS_POP
            self.ARM_INS_B, self.ARM_INS_BX, self.ARM_INS_BL, self.ARM_INS_BLX = (
                ARM_INS_B,
                ARM_INS_BX,
                ARM_INS_BL,
                ARM_INS_BLX,
            )
            self.ARM_INS_IT = ARM_INS_IT
            self.ARM_INS_CBZ, self.ARM_INS_CBNZ = ARM_INS_CBZ, ARM_INS_CBNZ
            self.ARM_INS_TBB, self.ARM_INS_TBH = ARM_INS_TBB, ARM_INS_TBH
            self.ARM_INS_LDR = ARM_INS_LDR
            self.ARM_INS_CMP = ARM_INS_CMP
            self.ARM_INS_MOV, self.ARM_INS_MOVW, self.ARM_INS_MOVT = (
                ARM_INS_MOV,
                ARM_INS_MOVW,
                ARM_INS_MOVT,
            )
            self.ARM_INS_BKPT = ARM_INS_BKPT
            self.ARM_INS_CPS = ARM_INS_CPS
            self.ARM_INS_SETEND = ARM_INS_SETEND
            self.ARM_INS_RET = -1

            self.ARM_OP_IMM, self.ARM_OP_MEM, self.ARM_OP_REG = (
                ARM_OP_IMM,
                ARM_OP_MEM,
                ARM_OP_REG,
            )
            self.ARM_REG_PC = ARM_REG_PC
            self.ARM_REG_CPSR = ARM_REG_CPSR
            self.ARM_REG_SP = ARM_REG_SP
            self.ARM_REG_IP = ARM_REG_IP
            self.ARM_REG_LR = ARM_REG_LR
            self.ARM_REG_ITSTATE = ARM_REG_ITSTATE

            self.ARM_GRP_INT, self.ARM_GRP_PRIVILEGE = ARM_GRP_INT, ARM_GRP_PRIVILEGE
            self.ARM_GRP_BRANCH_RELATIVE, self.ARM_GRP_JUMP, self.ARM_GRP_CALL = (
                ARM_GRP_BRANCH_RELATIVE,
                ARM_GRP_JUMP,
                ARM_GRP_CALL,
            )

            self.ARM_CC_HI = ARM_CC_HI
            self.ARM_CC_AL = ARM_CC_AL
            self.ARM_CC_INVALID = ARM_CC_INVALID

            self.dict_ldr_str = {
                ARM_INS_LDRBT: 1,
                ARM_INS_LDRB: 1,
                ARM_INS_LDRD: 8,
                ARM_INS_LDREX: 4,
                ARM_INS_LDREXB: 1,
                ARM_INS_LDREXD: 8,
                ARM_INS_LDREXH: 2,
                ARM_INS_LDRH: 2,
                ARM_INS_LDRHT: 2,
                ARM_INS_LDRSB: 1,
                ARM_INS_LDRSBT: 1,
                ARM_INS_LDRSH: 2,
                ARM_INS_LDRSHT: 2,
                ARM_INS_LDRT: 4,
                ARM_INS_LDR: 4,
                ARM_INS_STRBT: 1,
                ARM_INS_STRB: 1,
                ARM_INS_STRD: 8,
                ARM_INS_STREX: 4,
                ARM_INS_STREXB: 1,
                ARM_INS_STREXD: 8,
                ARM_INS_STREXH: 2,
                ARM_INS_STRH: 2,
                ARM_INS_STRHT: 2,
                ARM_INS_STRT: 4,
                ARM_INS_STR: 4,
            }

            self.ldr_str_simd = set(
                [
                    ARM_INS_VLD1,
                    ARM_INS_VLD2,
                    ARM_INS_VLD3,
                    ARM_INS_VLD4,
                    ARM_INS_VLDMDB,
                    ARM_INS_VLDMIA,
                    ARM_INS_VLDR,
                    ARM_INS_VST1,
                    ARM_INS_VST2,
                    ARM_INS_VST3,
                    ARM_INS_VST4,
                    ARM_INS_VSTMDB,
                    ARM_INS_VSTMIA,
                    ARM_INS_VSTR,
                ]
            )

            self.dict_cc_reverse = {
                ARM_CC_EQ: ARM_CC_NE,
                ARM_CC_HS: ARM_CC_LO,
                ARM_CC_MI: ARM_CC_PL,
                ARM_CC_VS: ARM_CC_VC,
                ARM_CC_HI: ARM_CC_LS,
                ARM_CC_GE: ARM_CC_LT,
                ARM_CC_GT: ARM_CC_LE,
                ARM_CC_NE: ARM_CC_EQ,
                ARM_CC_LO: ARM_CC_HS,
                ARM_CC_PL: ARM_CC_MI,
                ARM_CC_VC: ARM_CC_VS,
                ARM_CC_LS: ARM_CC_HI,
                ARM_CC_LT: ARM_CC_GE,
                ARM_CC_LE: ARM_CC_GT,
            }

            self.supported_insts = self.COMMON_INST_ID_32 | self.dict_ldr_str.keys() | self.ldr_str_simd

        elif self.aarch == 64:
            self.ARM_INS_NOP = ARM64_INS_NOP
            self.ARM_INS_POP = -1
            self.ARM_INS_B, self.ARM_INS_BX, self.ARM_INS_BL, self.ARM_INS_BLX = (
                ARM64_INS_B,
                -1,
                ARM64_INS_BL,
                -1,
            )
            self.ARM_INS_IT = -1
            self.ARM_INS_CBZ, self.ARM_INS_CBNZ = ARM64_INS_CBZ, ARM64_INS_CBNZ
            self.ARM_INS_TBB, self.ARM_INS_TBH = -1, -1
            self.ARM_INS_LDR = ARM64_INS_LDR
            self.ARM_INS_CMP = ARM64_INS_CMP
            self.ARM_INS_MOV, self.ARM_INS_MOVW, self.ARM_INS_MOVT = (
                ARM64_INS_MOV,
                -1,
                -1,
            )
            self.ARM_INS_BKPT = -1
            self.ARM_INS_CPS = -1
            self.ARM_INS_SETEND = -1
            self.ARM_INS_RET = ARM64_INS_RET

            self.ARM_OP_IMM, self.ARM_OP_MEM, self.ARM_OP_REG = (
                ARM64_OP_IMM,
                ARM64_OP_MEM,
                ARM64_OP_REG,
            )
            self.ARM_REG_PC = -1
            self.ARM_REG_CPSR = -1
            self.ARM_REG_SP = ARM64_REG_SP
            self.ARM_REG_IP = -1  # TODO: check
            self.ARM_REG_LR = ARM64_REG_LR
            self.ARM_REG_ITSTATE = -1

            self.ARM_GRP_INT, self.ARM_GRP_PRIVILEGE = (
                ARM64_GRP_INT,
                ARM64_GRP_PRIVILEGE,
            )
            self.ARM_GRP_BRANCH_RELATIVE, self.ARM_GRP_JUMP, self.ARM_GRP_CALL = (
                ARM64_GRP_BRANCH_RELATIVE,
                ARM64_GRP_JUMP,
                ARM64_GRP_CALL,
            )

            self.ARM_CC_HI = ARM64_CC_HI
            self.ARM_CC_AL = ARM64_CC_AL
            self.ARM_CC_INVALID = ARM64_CC_INVALID

            self.dict_ldr_str = {
                ARM64_INS_LDRB: 1,
                ARM64_INS_LDR: 4,
                ARM64_INS_LDRH: 2,
                ARM64_INS_LDRSB: 1,
                ARM64_INS_LDRSH: 2,
                ARM64_INS_LDRSW: 4,
                ARM64_INS_STRB: 1,
                ARM64_INS_STR: 4,
                ARM64_INS_STRH: 2,
            }

            self.ldr_str_simd = set()

            self.dict_cc_reverse = {
                ARM64_CC_EQ: ARM64_CC_NE,
                ARM64_CC_HS: ARM64_CC_LO,
                ARM64_CC_MI: ARM64_CC_PL,
                ARM64_CC_VS: ARM64_CC_VC,
                ARM64_CC_HI: ARM64_CC_LS,
                ARM64_CC_GE: ARM64_CC_LT,
                ARM64_CC_GT: ARM64_CC_LE,
                ARM64_CC_NE: ARM64_CC_EQ,
                ARM64_CC_LO: ARM64_CC_HS,
                ARM64_CC_PL: ARM64_CC_MI,
                ARM64_CC_VC: ARM64_CC_VS,
                ARM64_CC_LS: ARM64_CC_HI,
                ARM64_CC_LT: ARM64_CC_GE,
                ARM64_CC_LE: ARM64_CC_GT,
            }

    @staticmethod
    def addr_decode(addr):
        return addr if addr % 2 == 0 else addr - 1

    # from capstone/bindings/python/xprint.py
    @staticmethod
    def to_hex2(s):
        """
        if _python3:
            r = "".join("{0:02x}".format(c) for c in s)  # <-- Python 3 is OK
        else:
            r = "".join("{0:02x}".format(ord(c)) for c in s)
        """
        r = "".join("{0:02x}".format(c) for c in s)  # <-- Python 3 is OK
        while r[0] == "0":
            r = r[1:]
        return r

    @staticmethod
    def to_x(s):
        from struct import pack

        if not s:
            return "0"
        x = pack(">q", s)
        while x[0] in ("\0", 0):
            x = x[1:]
        return ARMDisassembler.to_hex2(x)

    @staticmethod
    def to_x_32(s):
        from struct import pack

        if not s:
            return "0"
        x = pack(">i", s)
        while x[0] in ("\0", 0):
            x = x[1:]
        # -print(x)
        return ARMDisassembler.to_hex2(x)

    def is_addr_in_section(self, addr):
        is_valid = False
        addr_decode = self.addr_decode(addr)
        for sec in self.sections:
            if (
                addr_decode >= self.sections[sec]["start_addr"]
                and addr_decode < self.sections[sec]["end_addr"]
            ):
                is_valid = True
                break
        return is_valid

    def is_addr_in_section_exec(self, addr):
        addr_decode = self.addr_decode(addr)
        for sec in self.sections_exec:
            if addr_decode == self.sections_exec[sec]["start_addr"]:
                return 1
            elif (
                addr_decode >= self.sections_exec[sec]["start_addr"]
                and addr_decode < self.sections_exec[sec]["end_addr"]
            ):
                return 0
        return -1

    def is_addr_in_section_data(self, addr):
        addr_decode = self.addr_decode(addr)
        for sec in self.sections_data:
            if addr_decode == self.sections_data[sec]["start_addr"]:
                return 1
            elif (
                addr_decode >= self.sections_data[sec]["start_addr"]
                and addr_decode < self.sections_data[sec]["end_addr"]
            ):
                return 0
        return -1

    def get_sectioninfo(self):
        b = self.binary
        b.read_sections()
        for sec in b.sections:
            self.sections[sec] = {}
            self.sections[sec]["content"] = b.sections[sec]["content"]
            self.sections[sec]["start_addr"] = b.sections[sec]["start_addr"]
            self.sections[sec]["end_addr"] = b.sections[sec]["end_addr"]
            self.sections[sec]["index"] = b.sections[sec]["index"]
            self.sections[sec]["size"] = b.sections[sec]["size"]
        
        self.sections_exec = b.sections_exec
        self.sections_data = b.sections_data
        return

    def generate_nodeinst(self, inst, inst_type):
        node_inst = NodeInst(inst=inst)
        node_inst.type = inst_type
        node_inst.size = inst.size

        node_inst.regs_read, node_inst.regs_write = inst.regs_access()
        node_inst.regs_read = set(node_inst.regs_read)
        node_inst.regs_write = set(node_inst.regs_write)

        # uncommon opcode
        # TODO:
        # - Improve the hints for more instructions based on distribution
        # - Too aggressive for unsupported insts
        if self.aarch == 32:
            if inst.id not in self.supported_insts:
                node_inst.hint = ARMDisassembler.S_UNCOMMON_OP

        return node_inst

    def superset_disasm(self):
        ss = dict()
        d = self.binary.disassembler

        if len(self.sections) < 1:
            self.get_sectioninfo()

        ## superset
        for sec in self.sections.keys():
            content = self.sections[sec]["content"]
            addr_start = self.sections[sec]["start_addr"]
            size = self.sections[sec]["size"]

            # disassembly arm
            for addr in range(addr_start, addr_start + size, 4):
                target_text = content[addr - addr_start : addr - addr_start + 4]
                cs_insts = d.disasm_arm_inst(target_text, addr)
                if len(cs_insts) == 1:
                    node_inst = self.generate_nodeinst(cs_insts[0], "A")
                    ss[addr] = node_inst
                    continue
                assert len(cs_insts) < 1, "Error: superset {}".format(addr)

            if self.aarch == 64:
                continue

            # disassembly thumb
            for addr in range(addr_start, addr_start + size, 2):
                # 2 bytes
                target_text = content[addr - addr_start : addr - addr_start + 2]
                cs_insts = d.disasm_thumb_inst(target_text, addr)
                if len(cs_insts) == 1:
                    node_inst = self.generate_nodeinst(cs_insts[0], "T")
                    ss[addr + 1] = node_inst
                    continue
                assert len(cs_insts) < 1, "Error: superset {}".format(addr)
                # else: 4 bytes
                target_text = content[addr - addr_start : addr - addr_start + 4]
                cs_insts = d.disasm_thumb_inst(target_text, addr)
                if len(cs_insts) == 1:
                    node_inst = self.generate_nodeinst(cs_insts[0], "T")
                    ss[addr + 1] = node_inst
                    continue
                assert len(cs_insts) < 1, "Error: superset {}".format(addr)

        # self.superset = ss
        return ss

    def initial_data_node(self, ss):
        # logging.info("[+] Initial Data Node")
        if len(self.sections) < 1:
            self.get_sectioninfo()
        for sec in self.sections:
            for addr in range(
                self.sections[sec]["start_addr"], self.sections[sec]["end_addr"]
            ):
                self.data[addr] = NodeData()

        return

    def update_superset_successor(self, ss):
        for addr, node_inst in ss.items():
            inst = node_inst.inst
            set_bit = (addr - inst.address) & 1
            succr1, succr2 = self.get_successor_basic(node_inst, set_bit)
            ## TODO: change for superset_addr
            # node_inst.succr1 = successor1
            # node_inst.succr2 = successor2
            for succr in [succr1, succr2]:
                if succr > -1:
                    node_inst.succr.append(succr)
        return ss

    def update_superset_successor_infer(self, ss):
        if len(self.sections) < 1:
            self.get_sectioninfo()
        set_it_invalid = set(
            [
                self.ARM_INS_IT,
                self.ARM_INS_CBZ,
                self.ARM_INS_CBNZ,
                self.ARM_INS_TBB,
                self.ARM_INS_TBH,
                self.ARM_INS_CPS,
                self.ARM_INS_SETEND,
            ]
        )

        for addr, node_inst in ss.items():
            inst = node_inst.inst
            # set_bit = (addr - inst.address) & 1
            # print(node_inst.type, set_bit)
            succrs_inst, succrs_data = self.get_successor_infer(inst, addr, ss)

            if inst.id == self.ARM_INS_NOP:
                node_inst.succr = list()
            elif inst.id == self.ARM_INS_MOV:
                # if ss[addr].regs_write == ss[addr].regs_read:
                ## mov rn, rn
                if ss[addr].inst.operands[1].type == self.ARM_OP_REG and set(
                    ss[addr].regs_write
                ).issuperset(ss[addr].regs_read):
                    node_inst.succr = list()
                if self.ARM_REG_PC in ss[addr].regs_write:
                    if inst.cc != self.ARM_CC_AL and inst.cc != self.ARM_CC_INVALID:
                        continue
                    node_inst.succr = list()
            ## for it, fix the basic succr of its following insts
            elif inst.id == self.ARM_INS_IT:
                it = list()
                is_valid_it = True
                addr_curr = addr
                for i in range(1, len(inst.mnemonic)):
                    cond = inst.mnemonic[i]
                    if cond != "t" and cond != "e":
                        break
                    while True:
                        addr_curr = addr_curr + ss[addr_curr].size
                        if addr_curr not in ss:
                            is_valid_it = False
                            break
                        if ss[addr_curr].inst.id != self.ARM_INS_BKPT:
                            # TODO: also pc
                            # A branch or any instruction that modifies the PC is only permitted in an IT block if it is the last instruction in the block
                            if ss[addr_curr].inst.id in set_it_invalid:
                                is_valid_it = False
                            if i < len(inst.mnemonic) - 1 and inst.mnemonic[i + 1] in [
                                "t",
                                "e",
                            ]:
                                set_groups = set(ss[addr_curr].inst.groups)
                                if (
                                    self.ARM_GRP_BRANCH_RELATIVE in set_groups
                                    or self.ARM_GRP_JUMP in set_groups
                                    or self.ARM_GRP_CALL in set_groups
                                ):
                                    is_valid_it = False
                                # regs_write = ss[addr_curr].inst.regs_access()[1]
                                regs_write = ss[addr_curr].regs_write
                                if self.ARM_REG_PC in regs_write:
                                    is_valid_it = False
                            break
                    if not is_valid_it:
                        break
                    it.append([addr_curr, cond])

                if not is_valid_it:
                    node_inst.hint = -100
                    continue

                # update the succr of each inst in the it block
                addr_last_t, addr_last_e = it[0][0], addr
                for i in range(1, len(it)):
                    if it[i][1] != it[i - 1][1]:
                        if it[i][0] in ss[it[i - 1][0]].succr:
                            ss[it[i - 1][0]].succr.remove(it[i][0])
                            addr_last = addr_last_t if it[i][1] == "t" else addr_last_e
                            ss[addr_last].succr.append(it[i][0])
                    if it[i][1] == "t":
                        addr_last_t = it[i][0]
                    else:
                        addr_last_e = it[i][0]

                # add the first inst after the block as the succr of inst/addr_last_t/addr_last_e
                addr_after_it = addr_curr + ss[addr_curr].size
                # only "t"
                # if addr_after_it not in ss and "e" not in [item[1] for item in it]:
                if addr_after_it not in ss:
                    node_inst.hint = -100
                    continue

                for addr_todo in set([addr, addr_last_t, addr_last_e]):
                    if addr_todo == addr_curr:
                        set_groups = set(ss[addr_todo].inst.groups)
                        if (
                            self.ARM_GRP_BRANCH_RELATIVE in set_groups
                            or self.ARM_GRP_JUMP in set_groups
                            or self.ARM_GRP_CALL in set_groups
                        ):
                            continue
                    if addr_after_it not in ss[addr_todo].succr:
                        ss[addr_todo].succr.append(addr_after_it)
            elif inst.id == self.ARM_INS_TBB or inst.id == self.ARM_INS_TBH:
                # check cmp/bhi pattern
                pattern = list()
                for addr_b in [addr - 2, addr - 4]:
                    if addr_b in ss and ss[addr_b].inst.id == self.ARM_INS_B:
                        for addr_cmp in [addr_b - 2, addr_b - 4]:
                            if (
                                addr_cmp in ss
                                and ss[addr_cmp].inst.id == self.ARM_INS_CMP
                            ):
                                pattern.append([addr_cmp, addr_b])
                if len(pattern) == 0:
                    node_inst.hint = -100
                    continue
                elif len(pattern) > 1:
                    logging.info("tbb/tbh with multiple patterns: {}".format(pattern))

                len_byte = 1 if inst.id == self.ARM_INS_TBB else 2
                for addr_cmp, addr_b in pattern:
                    if (
                        len(ss[addr_cmp].inst.operands) == 2
                        and ss[addr_cmp].inst.operands[1].type == self.ARM_OP_IMM
                    ):
                        num_b = ss[addr_cmp].inst.operands[1].imm + 1
                    else:
                        continue

                    if ss[addr_b].inst.cc != self.ARM_CC_HI:
                        logging.info(
                            "tbb/tbh unexpected pattern: {} {}".format(addr_cmp, addr_b)
                        )
                        continue

                    # decide succrs_data
                    for i in range(num_b * len_byte):
                        addr_d = self.addr_decode(addr) + inst.size + i
                        succrs_data.append(addr_d)
                    if inst.id == self.ARM_INS_TBB and num_b % 2 == 1:
                        succrs_data.append(addr_d + 1)

                    # decide succrs_inst
                    # rn needs to be pc
                    if inst.operands[0].mem.base != self.ARM_REG_PC:
                        continue

                    addr_d = self.addr_decode(addr) + inst.size
                    for sec in self.sections:
                        if (
                            addr_d >= self.sections[sec]["start_addr"]
                            and addr_d < self.sections[sec]["end_addr"]
                        ):
                            l = addr_d - self.sections[sec]["start_addr"]
                            r = l + num_b * len_byte
                            contents = self.sections[sec]["content"][l:r]
                    for i in range(num_b):
                        value = contents[i * len_byte : (i + 1) * len_byte]
                        if len(value) == 1:
                            offset = value[0]
                        else:
                            offset = struct.unpack("<H", value)[0]
                        succrs_inst.append(addr + 4 + offset * 2)

                    # print info for check
                    # for addr_todo in [addr_cmp, addr_b, addr]:
                    #     inst_curr = ss[addr_todo].inst
                    #     print("{} {} {}".format(hex(addr_todo), inst_curr.mnemonic, inst_curr.op_str))
                    # print(" data: {}".format([hex(a) for a in succrs_data]))
                    # print(" inst: {}".format([hex(a) for a in succrs_inst]))
            elif (
                self.ARM_REG_PC in ss[addr].regs_write
                and not (inst.cc != self.ARM_CC_AL and inst.cc != self.ARM_CC_INVALID)
                and addr + inst.size in node_inst.succr
            ):
                # logging.debug(f"write pc {hex(addr)} {ss[addr].inst.mnemonic} {ss[addr].inst.op_str}")
                # if inst.id in set_write_pc:
                node_inst.succr.remove(addr + inst.size)

            for succr in succrs_inst:
                if succr not in node_inst.succr:
                    node_inst.succr.append(succr)
            for succr in succrs_data:
                if succr not in node_inst.succr_data and succr in self.data:
                    node_inst.succr_data.append(succr)
                    self.data[succr].accessed_inst.append(addr)

        return ss

    def get_successor_basic(self, node_inst, set_bit):
        inst = node_inst.inst

        successor1, successor2 = -1, -1
        succrs = list()
        set_groups = set(inst.groups)

        if inst.id == self.ARM_INS_TBB or inst.id == self.ARM_INS_TBH:
            ## TODO, if rn is pc, not return -1
            return -1, -1
        elif inst.id == self.ARM_INS_NOP:
            return -1, -1
        # aarch64
        elif inst.id == self.ARM_INS_RET:
            return -1, -1
        # fix pop successor
        # inst.regs_access includes all the implicit & explicit registers
        # (regs_read, regs_write) = inst.regs_access()
        # inst.regs_write return list of all implicit registers being modified
        # error: reg_write is always PC
        elif inst.id == self.ARM_INS_POP:
            if self.ARM_REG_PC in node_inst.regs_write:
                return -1, -1
        elif (
            self.ARM_GRP_BRANCH_RELATIVE in set_groups
            or self.ARM_GRP_JUMP in set_groups
            or self.ARM_GRP_CALL in set_groups
        ):
            # cbz/cbnz/conditional branch: the next inst is its succr
            if inst.id == self.ARM_INS_CBZ or inst.id == self.ARM_INS_CBNZ:
                succrs.append((inst.address + node_inst.size) | set_bit)
            elif inst.cc != self.ARM_CC_AL and inst.cc != self.ARM_CC_INVALID:
                succrs.append((inst.address + node_inst.size) | set_bit)

            # b/bl/blx label
            if len(inst.operands) == 1 and inst.operands[0].type == self.ARM_OP_IMM:
                target = (
                    int(ARMDisassembler.to_x_32(inst.operands[0].imm), 16)
                    if inst.operands[0].imm < 0
                    else inst.operands[0].imm
                )
                target = target | set_bit
                # fix bx/blx imm successor
                if inst.id == self.ARM_INS_BX or inst.id == self.ARM_INS_BLX:
                    target ^= 1
                succrs.append(target)
            # cbz/cbnz: the immediate is also its succr
            elif len(inst.operands) == 2 and inst.operands[1].type == self.ARM_OP_IMM:
                target = (
                    int(ARMDisassembler.to_x_32(inst.operands[1].imm), 16)
                    if inst.operands[1].imm < 0
                    else inst.operands[1].imm
                )
                target = target | set_bit
                succrs.append(target)

            if len(succrs) == 1:
                successor1 = succrs[0]
            elif len(succrs) == 2:
                successor1, successor2 = succrs[0], succrs[1]
            return successor1, successor2
        elif self.ARM_GRP_INT in set_groups or self.ARM_GRP_PRIVILEGE in set_groups:
            return -1, -1

        successor1 = (inst.address + node_inst.size) | set_bit

        return successor1, successor2

    def get_successor_infer(self, inst, addr, ss):
        succrs_inst, succrs_data = list(), list()
        set_groups = set(inst.groups)
        set_bit = (addr - inst.address) & 1

        if (
            self.ARM_GRP_BRANCH_RELATIVE in set_groups
            or self.ARM_GRP_JUMP in set_groups
            or self.ARM_GRP_CALL in set_groups
        ):
            ## consider pc as the target
            if len(inst.operands) == 1 and inst.operands[0].type == self.ARM_OP_REG:
                if inst.operands[0].reg == self.ARM_REG_PC:
                    target = inst.address + 4 if set_bit == 1 else inst.address + 8
                    succrs_inst.append(target)

            if inst.id == self.ARM_INS_BL or inst.id == self.ARM_INS_BLX:
                pass
                # TODO: chec if it returns
                # succrs_inst.append((inst.address + inst.size) | set_bit)
            elif inst.id == self.ARM_INS_TBB or inst.id == self.ARM_INS_TBH:
                pass

        elif inst.id in self.dict_ldr_str:
            op = inst.operands[1]
            # print("LDR/STR: {} {} {} {} {} {} {} {}".format(hex(inst.address), inst.mnemonic, inst.op_str,\
            #    op.mem.base, op.mem.index, op.mem.scale, op.mem.disp, op.mem.lshift))
            if op.type == self.ARM_OP_MEM and op.mem.base == self.ARM_REG_PC:
                if op.mem.index == 0 and op.mem.scale == 1 and op.mem.lshift == 0:
                    if op.mem.base == self.ARM_REG_PC:
                        target = inst.address + 4 if set_bit == 1 else inst.address + 8
                        target += op.mem.disp
                        # if set_bit == 1 and target % 4 != 0:
                        #    target = target - 2
                        succrs_data.append(target)
                        # print(" target: {}".format(hex(target)))
            elif op.type == self.ARM_OP_IMM:
                target = (
                    int(ARMDisassembler.to_x_32(op.imm), 16)
                    if op.imm < 0
                    else op.imm
                )
                succrs_data.append(target)

        # elif inst.id == ARM_INS_IT:
        # print(inst.mnemonic, inst.op_str)

        return succrs_inst, succrs_data

    def update_superset_pred(self, ss):
        # logging.info("[+] Update Superset Pred")
        for addr, node_inst in ss.items():
            for succr in node_inst.succr:
                if succr in ss:
                    ss[succr].pred.append(addr)
        return ss

    def print_superset_info(self, ss):
        for addr in sorted(ss.keys()):
            node_inst = ss[addr]
            inst = node_inst.inst
            bytes = "".join(format(x, "02x") for x in inst.bytes)
            print(
                "{} {} {:>8} {} {}".format(
                    hex(addr), node_inst.type, bytes, inst.mnemonic, inst.op_str
                )
            )
            # [hex(a) for a in node_inst.succr]
            # [hex(a) for a in node_inst.pred]
            # node_inst.hint, self.hint_dl[addr][1], self.hint_scores[addr]
            # [hex(a) for a in node_inst.succr_data]

    ## Hints ##

    def static_analysis(self, ss):
        for addr in ss:
            self.hint_scores[addr] = [1, 0, 0, 0]

        self.addr_sorted = sorted(ss.keys())
        self.get_cf_converge_hints(ss)
        self.get_cf_cross_hints(ss)
        # self.get_reg_hints(ss)
        # self.get_reg_hints_onepass(ss)
        self.get_reg_hints_limited(ss)

        return

    def get_cf_converge_hints(self, ss):
        # get mapping from jump target to jump-site
        dst2src = defaultdict(list)
        addr_list = self.addr_sorted
        for addr in addr_list:
            for succr in ss[addr].succr:
                if succr == -1 or succr == addr + ss[addr].size:
                    continue
                dst2src[succr].append(addr)

        # check converge control flow
        for addr, src_list in dst2src.items():
            l = len(src_list)
            for src in src_list:
                self.hint_scores[src][1] += l - 1

        return

    def get_cf_cross_hints(self, ss):
        addr_list = self.addr_sorted
        for addr in addr_list:
            # check inst is a jump/call instruction
            jump_target = -1
            for succr in ss[addr].succr:
                if succr == -1 or succr == addr + ss[addr].size:
                    continue
                jump_target = succr
            # No jump target find
            if jump_target == -1:
                continue

            # check control flow cross
            for offset in range(2, 5, 2):
                addr_pre = jump_target - offset

                # check pre_addr is valid
                if addr_pre not in ss or ss[addr_pre].size != offset:
                    continue

                # check pre_inst is jump instruction
                is_jump = False
                for g in ss[addr_pre].inst.groups:
                    if g in [
                        self.ARM_GRP_BRANCH_RELATIVE,
                        self.ARM_GRP_JUMP,
                        self.ARM_GRP_CALL,
                    ]:  ## TODO: check
                        is_jump = True
                        break

                if is_jump:
                    self.hint_scores[addr][2] += 1
                    self.hint_scores[addr_pre][2] += 1

        return

    def get_reg_hints(self, ss):
        addr_list = self.addr_sorted
        for addr in addr_list:
            # For each insturction, check registers written by it. Hence, we do not
            # need to care instructions which do not write any register.
            inst = ss[addr].inst
            # regs_write = inst.regs_access()[1]
            regs_write = inst.regs_write
            if len(regs_write) == 0:
                continue

            # Collect written register
            write_regs = dict()
            for r in regs_write:
                write_regs[r] = 1

            # DFS to gather hints
            visited = set()
            for succr in ss[addr].succr:
                if succr == -1:
                    continue
                self.dfs_get_reg_hints(ss, addr, succr, write_regs, visited)

            del write_regs

        return

    def dfs_get_reg_hints(self, ss, addr_def, addr_cur, write_regs, visited):
        # update visitied
        visited.add(addr_cur)

        # validate address
        if addr_cur not in ss:
            return

        # check use-def chain
        inst = ss[addr_cur].inst
        # regs_read = inst.regs_access()[0]
        regs_read = inst.regs_read

        # generate hints and record removed registers
        removed_regs = list()
        for r in regs_read:
            # ignore flags and pc register
            if r == self.ARM_REG_CPSR or r == self.ARM_REG_PC:
                continue

            if r in write_regs:
                self.hint_scores[addr_def][3] += 1
                self.hint_scores[addr_cur][3] += 1

                removed_regs.append(r)
                del write_regs[r]

        # check successors
        if len(write_regs) > 0:
            for succr in ss[addr_cur].succr:
                if succr == -1:
                    break

                if succr in visited:
                    continue

                self.dfs_get_reg_hints(ss, addr_def, succr, write_regs, visited)

        # restore removed registers
        for r in removed_regs:
            write_regs[r] = 1

        return

    def get_reg_hints_limited(self, ss):
        set_reg_ignored = set(
            [self.ARM_REG_CPSR, self.ARM_REG_PC, self.ARM_REG_ITSTATE]
        )
        addr_list = self.addr_sorted
        for addr in addr_list:
            # For each insturction, check registers written by it. Hence, we do not
            # need to care instructions which do not write any register.

            # Collect written register
            write_regs = dict()
            for r in ss[addr].regs_write:
                if r in set_reg_ignored:
                    # or self.ARM_REG_IP: #or r == self.ARM_REG_SP:
                    continue
                write_regs[r] = 1

            if len(write_regs) == 0:
                continue

            # DFS to gather hints
            visited = set()
            for succr in ss[addr].succr:
                if succr == -1:
                    continue
                self.dfs_get_reg_hints_limited(
                    ss, addr, succr, write_regs, visited, 1000, False
                )

            del write_regs
        return

    def dfs_get_reg_hints_limited(
        self, ss, addr_def, addr_cur, write_regs, visited, depth, pass_branch
    ):
        # update visitied
        visited.add(addr_cur)

        # validate address
        if addr_cur not in ss:
            return

        # check use-def chain
        # generate hints and record removed registers
        removed_regs = list()
        for r in ss[addr_cur].regs_read:
            # ignore flags and pc register
            # if r == self.ARM_REG_CPSR or r == self.ARM_REG_PC:
            #    continue

            if r in write_regs:
                self.hint_scores[addr_def][3] += 1
                self.hint_scores[addr_cur][3] += 1

                removed_regs.append(r)
                del write_regs[r]

        if self.ARM_REG_PC in ss[addr_cur].regs_write:
            pass_branch = True
        # Or check if ARM_REG_ITSTATE/ARM_REG_ITSTATE in ss[addr_cur].regs_write:
        if ss[addr_cur].inst.id == self.ARM_INS_CMP or ss[addr_cur].inst.id == ARM_INS_CMN:
            pass_branch = True

        for r in ss[addr_cur].regs_write:
            if r in write_regs:
                if r in set([self.ARM_REG_IP, self.ARM_REG_LR]):
                    continue
                if not pass_branch:
                    # TODO: check the score
                    self.hint_scores[addr_def][3] += -10
                removed_regs.append(r)
                del write_regs[r]

        # check successors
        if len(write_regs) > 0 and depth > 0:
            for succr in ss[addr_cur].succr:
                if succr not in ss:
                    continue

                if succr in visited:
                    continue

                self.dfs_get_reg_hints_limited(
                    ss, addr_def, succr, write_regs, visited, depth - 1, pass_branch
                )

        # restore removed registers
        for r in removed_regs:
            write_regs[r] = 1

        return

    def read_analysis_hints(self, ss):
        assert os.path.isfile(
            self.filepath_hint_analysis
        ), "hint result doesn't exist: {}".format(self.filepath_hint_analysis)

        with open(self.filepath_hint_analysis) as f:
            line_list = f.read().splitlines()

        for line in line_list:
            line_info = line.split()
            addr = int(line_info[3])
            self.hint_scores[addr] = [
                1,
                int(line_info[0]),
                int(line_info[1]),
                int(line_info[2]),
            ]
        return

    def save_analysis_hints(self, ss):
        with open(self.filepath_hint_analysis, "w") as f:
            # for addr in sorted(ss.keys()):
            for addr in self.addr_sorted:
                f.write(
                    "{0[1]} {0[2]} {0[3]} {1} {2}\n".format(self.hint_scores[addr], addr, hex(addr))
                )
        return

    def compute_analysis_hint_scores(self, ss):
        for addr in ss:
            self.hint_scores[addr][0] = (
                self.hint_scores[addr][1] * 0.1
                + self.hint_scores[addr][2] * 0.01
                + self.hint_scores[addr][3] * 0.01
            )

            # method 2:
            # self.hint_scores[addr][0] = 0
            # if self.hint_scores[addr][1] > 0:
            #     for i in range(self.hint_scores[addr][1]):
            #         self.hint_scores[addr][0] *= ARMDisassembler.HT_CF_CONVERGE
            # if self.hint_scores[addr][2] > 0:
            #     for i in range(self.hint_scores[addr][2]):
            #         self.hint_scores[addr][0] *= ARMDisassembler.HT_CF_CROSS
            # if self.hint_scores[addr][3] > 0:
            #     for i in range(self.hint_scores[addr][3]):
            #         self.hint_scores[addr][0] *= ARMDisassembler.HT_REG
            # self.hint_scores[addr][0] = 1 - self.hint_scores[addr][0]

        return

    def add_data_hint_readable_string(self):
        if self.aarch == 32:
            T_MIM_L = 6
        elif self.aarch == 64:
            T_MIM_L = 8

        if len(self.sections) < 1:
            self.get_sectioninfo()

        for sec in self.sections:
            content = self.sections[sec]["content"]
            addr_start = self.sections[sec]["start_addr"]

            i = 0
            while i < len(content):
                j = i
                while (
                    (content[j] >= 33 and content[j] <= 63)
                    or (content[j] > 96 and content[j] < 126)
                ) and content[j] != 0:
                    j += 1
                if content[j] == 0 and j - i >= T_MIM_L:
                    l = j - i + 1
                    # logging.debug("string {} {}".format(content[i:j+1], l))
                    for addr in range(addr_start + i, addr_start + j + 1):
                        self.data[addr].hint += 0.2 * l
                i = j + 1
        return

    def check_common_pattern(self, ss):
        """
        - hard code the start of func
        - if the start of a cf is: ldr, push, add
        - bl + ldr: incorrect
        - cmp + b{cond}

        - b close_target
        - movw movt
        """
        set_close_target = set([self.ARM_INS_BL, self.ARM_INS_B])
        for addr in sorted(ss.keys()):
            if ss[addr].inst.id in set_close_target:
                if len(ss[addr].succr) == 1:
                    addr_target = ss[addr].succr[0]
                    if (
                        addr_target not in ss
                        or addr_target == addr + ss[addr].size
                        or addr_target < addr
                        or addr_target > addr + ss[addr].size + 4
                    ):
                        continue
                    new_data = set()
                    if addr_target - addr - ss[addr].size == 2:
                        a = addr + ss[addr].size
                        if not (
                            a in ss
                            and ss[a].size == 2
                            and (
                                len(ss[a].pred) > 0 or ss[a].inst.id == self.ARM_INS_LDR
                            )
                        ):
                            new_data.add(a)
                    else:
                        a1, a2 = addr + ss[addr].size, addr + ss[addr].size + 2
                        if a1 not in ss:
                            new_data.add(a1)
                            if not (
                                a2 in ss
                                and ss[a2].size == 2
                                and (
                                    len(ss[a2].pred) > 0
                                    or ss[a2].inst.id == self.ARM_INS_LDR
                                )
                            ):
                                new_data.add(a2)
                        else:
                            if ss[a1].size == 2:
                                if not (
                                    a2 in ss
                                    and ss[a2].size == 2
                                    and (
                                        len(ss[a1].pred) > 0
                                        or ss[a1].inst.id == self.ARM_INS_LDR
                                    )
                                ):
                                    new_data.update([a1, a2])
                            elif ss[a1].size == 4:
                                if not (
                                    len(ss[a1].pred) > 0
                                    or ss[a1].inst.id == self.ARM_INS_LDR
                                ):
                                    new_data.add(a1)
                    for a in new_data:
                        a_decode = self.addr_decode(a)
                        if a_decode not in ss[addr].succr_data:
                            ss[addr].succr_data.append(a_decode)
                            self.data[a_decode].accessed_inst.append(addr)
                        if a in ss:
                            ss[a].hint += ARMDisassembler.S_CLOSE_TARGET
            elif ss[addr].inst.id == self.ARM_INS_BX:
                if not (len(ss[addr].inst.operands) == 1 and ss[addr].inst.operands[0].type == self.ARM_OP_REG and ss[addr].inst.operands[0].reg == self.ARM_REG_LR):
                    continue
                for addr_pred in ss[addr].pred:
                    if addr_pred in ss and ss[addr_pred].inst.id in self.ldr_str_simd:
                        if ss[addr_pred].inst.id not in self.supported_insts:
                            ss[addr_pred].hint -= ARMDisassembler.S_UNCOMMON_OP
                        ss[addr_pred].hint += ARMDisassembler.S_COMMON_BASIC
            elif ss[addr].inst.id == self.ARM_INS_MOVW:
                addr_next = addr + ss[addr].size
                if addr_next in ss and ss[addr_next].inst.id == self.ARM_INS_MOVT:
                    ss[addr].hint += ARMDisassembler.S_MOVW_MOVT

        return ss

    def update_succr_scores(self, ss):
        for addr in ss:
            for succr_inst in ss[addr].succr:
                valid_score = self.is_addr_in_section_exec(succr_inst)
                if valid_score > 0:
                    ss[addr].hint += self.ADDR_SUCCR_PERFECT
                elif valid_score == 0:
                    ss[addr].hint += self.ADDR_SUCCR_VALID
            for succr_data in ss[addr].succr_data:
                valid_score = self.is_addr_in_section_data(succr_data)
                if valid_score > 0:
                    ss[addr].hint += self.ADDR_SUCCR_PERFECT
                elif valid_score == 0:
                    ss[addr].hint += self.ADDR_SUCCR_VALID
                # TODO: check
                # if self.is_addr_in_section(succr_data):
                if self.is_addr_in_section_exec(succr_data) >= 0:
                    ss[addr].hint += self.ADDR_SUCCR_VALID

        return
    
    def compute_node_weights(self, ss):
        self.add_data_hint_readable_string()
        self.compute_analysis_hint_scores(ss)
        self.check_common_pattern(ss)
        self.update_succr_scores(ss)
        return

    def print_scores_inst(self, ss):
        for addr in sorted(ss.keys()):
            node_inst = ss[addr]
            inst = node_inst.inst
            bytes = "".join(format(x, "02x") for x in inst.bytes)
            print(
                "{} {} {:>8} {} {} {} {}".format(
                    hex(addr), node_inst.type, bytes, ss[addr].hint, self.hint_scores[addr], inst.mnemonic, inst.op_str
                )
            )
    
    def print_scores_data(self):
        for addr in sorted(self.data.keys()):
            print("{} {} {}".format(hex(addr), self.data[addr].type, self.data[addr].hint))

    def dfs_addr_all_check_invalid(self, ss, addr, visited):
        if addr in visited:
            return visited

        ## for condition jump, if is possible one succ is invalid
        if len(ss[addr].succr) > 1:
            return visited
        visited.add(addr)
        node_inst = ss[addr]
        for succr in node_inst.succr:
            if succr in ss and succr not in visited:
                visited = self.dfs_addr_all_check_invalid(ss, succr, visited)
        for pred in node_inst.pred:
            if pred in ss and pred not in visited:
                visited = self.dfs_addr_all_check_invalid(ss, pred, visited)

        return visited

    def update_superset_with_invalid_nodes(self, superset):
        ss = dict()
        addr_remove = set()
        for addr in superset:
            ## Remove inst_node from superset if it has invalid succr
            if len(superset[addr].succr) == 1:
                a = superset[addr].succr[0]
                # if a not in superset and self.is_addr_in_section(a):
                if self.is_addr_in_section_exec(a) < 0:
                    addr_remove = self.dfs_addr_all_check_invalid(
                        superset, addr, addr_remove
                    )
        
        # TODO: need to update after adding more scores

        # Update superset
        for addr in superset:
            # TODO: check if it is necessary
            # superset[addr].inst = None
            if addr in addr_remove:
                continue
            ss[addr] = superset[addr]
            ss[addr].overlapped_inst = set()
            ss[addr].overlapped_data = set()
        return ss

    def dfs_addr_all(self, ss, addr, visited):
        if addr in visited:
            return visited
        visited.add(addr)
        node_inst = ss[addr]
        for succr in node_inst.succr:
            if succr in ss and succr not in visited:
                visited = self.dfs_addr_all(ss, succr, visited)
        for pred in node_inst.pred:
            if pred in ss and pred not in visited:
                visited = self.dfs_addr_all(ss, pred, visited)

        return visited

    def dfs_addr_succr_greedy(self, ss, addr, visited):
        if addr in visited:
            return visited

        visited.add(addr)
        node_inst = ss[addr]

        for succr in node_inst.succr:
            if succr in ss and succr not in visited and succr not in self.inst_selected:
                visited = self.dfs_addr_succr_greedy(ss, succr, visited)

        return visited

    def compute_control_flow(self, ss):
        # logging.info("[+] Compute Control Flow")
        cf_all = list()
        visited_all = set()
        for addr in ss:
            if addr not in visited_all:
                visited = sorted(self.dfs_addr_all(ss, addr, set()))
                cf_all.append(visited)
                visited_all.update(visited)
        return cf_all

    def dfs_addr_reachable(self, ss, addr, addr_reachable):
        addr_reachable[addr].add(addr)

        for pred in ss[addr].pred:
            if (
                pred in ss
                and addr not in addr_reachable[pred]
                and not addr_reachable[addr].issubset(addr_reachable[pred])
            ):
                addr_reachable[pred].update(addr_reachable[addr])
                addr_reachable = self.dfs_addr_reachable(ss, pred, addr_reachable)

        return addr_reachable

    def aggregate_weights(self, ss):
        cf_all = self.compute_control_flow(ss)

        aggregated_scores = dict()
        for i, cf in enumerate(cf_all):
            addr_reachable = dict()
            addr_end = list()
            for addr in cf:
                is_end = True
                for succr in ss[addr].succr:
                    if succr in ss:
                        is_end = False
                        break
                if is_end:
                    addr_end.append(addr)
                addr_reachable[addr] = set()
            if len(addr_end) == 0:
                addr_end.append(cf[-1])

            for addr in addr_end:
                addr_reachable = self.dfs_addr_reachable(ss, addr, addr_reachable)

            # compute the aggregated weights
            for addr in cf[::-1]:
                if addr not in aggregated_scores:
                    aggregated_scores[addr] = 0
                ss[addr].addr_reachable = addr_reachable[addr]

                # TODO: replace 1 with lstm hint
                # score_basic = self.hint_dl[addr][1]

                # method 0:
                # aggregated_scores[addr] = self.hint_dl[addr][1]
                # aggregated_scores[addr] = self.hint_scores[addr][0]
                # aggregated_scores[addr] = self.hint_dl[addr][1] + self.hint_scores[addr][0] # pad_0

                # method 1: max, hint_xda + hint_scores(add)
                # error: == score_basic
                # aggregated_scores[addr] = max([score_basic + self.hint_scores[x][0] for x in addr_reachable[addr]])
                # aggregated_scores[addr] = max([self.hint_dl[x][1] for x in addr_reachable[addr]])
                # aggregated_scores[addr] = max([self.hint_scores[x][0] for x in addr_reachable[addr]])
                # aggregated_scores[addr] = max([self.hint_dl[x][1] + self.hint_scores[x][0] for x in addr_reachable[addr]])

                # method 2: sum, hint_xda - hint_scores(multiply)
                # aggregated_scores[addr] = sum([self.hint_scores[x][0] for x in addr_reachable[addr]])
                # aggregated_scores[addr][0] = sum([score_basic - self.hint_scores[x][0] for x in aggregated_scores[addr][1]])
                # aggregated_scores[addr][0] = sum([ss[x]['h'] for x in aggregated_scores[addr][1]])
                # aggregated_scores[addr] = sum([self.hint_dl[x][1] + self.hint_scores[x][0] for x in addr_reachable[addr]])

                # method 3: sum, hint_xda + hint_scores - ave(hint_data)
                # aggregated_scores[addr] = sum([self.hint_scores[x][0] - np.mean(ss[x].score_data) for x in addr_reachable[addr]])
                # aggregated_scores[addr] = sum([self.hint_dl[x][1] + self.hint_scores[x][0] - np.mean(ss[x].score_data) for x in addr_reachable[addr]])

                # method 4: score * num_reachable_node
                # aggregated_scores[addr] = self.hint_dl[addr][1] * len(addr_reachable[addr]) # pad_2
                aggregated_scores[addr] = self.hint_scores[addr][0] * len(
                    addr_reachable[addr]
                )
                # aggregated_scores[addr] = (self.hint_dl[addr][1] + self.hint_scores[addr][0])/2 * len(addr_reachable[addr])
                # aggregated_scores[addr] = (self.hint_dl[addr][1] +
                #                            self.hint_scores[addr][0]) * len(
                #                                addr_reachable[addr])  # pad_1

                # if self.hint_scores[addr][3] < 0:
                # aggregated_scores[addr] = min(0.1, aggregated_scores[addr])
                # ggregated_scores[addr] = 0.1 * len(addr_reachable[addr])

                # logging.debug("{} {} {}".format(addr, aggregated_scores[addr][0], aggregated_scores[addr][1]))
                # logging.debug("{} {} {}".format(hex(addr), aggregated_scores[addr][0], [hex(a) for a in aggregated_scores[addr][1]]))

                if ss[addr].hint < 0:
                    continue
                if self.hint_scores[addr][3] < 0:
                    ss[addr].hint = self.hint_scores[addr][3]
                    continue
                ss[addr].hint += aggregated_scores[addr]
        return

    def greedy_add(self, inst_new, data_new, ss, addr_cur):
        is_valid = True
        inst_new_total, data_new_total = set(), set()
        inst_remove_total, data_remove_total = set(), set()

        data_type_changed = list()
        while len(inst_new) > 0 or len(data_new) > 0:
            data_new_tmp, inst_new_tmp = set(), set()
            data_remove, inst_remove = set(), set()
            score_sum_inst_new = 0
            for a in inst_new:
                # make sure a must be in self.inst_todo
                a_decode = self.addr_decode(a)
                score_sum_inst_new += ss[a].hint

                data_new.update(
                    [
                        a_data
                        for a_data in ss[a].succr_data
                        if a_data not in self.data_selected
                    ]
                )
                ## remove inst/data that conflicts with inst_new
                data_remove.update([a_data for a_data in ss[a].overlapped_data])
                inst_remove.update([a_i for a_i in ss[a].overlapped_inst])
            if score_sum_inst_new < 0:
                is_valid = False
                logging.debug(
                    "Invalid {}: the score_sum of inst_new is samll {}".format(
                        hex(addr_cur), score_sum_inst_new
                    )
                )
                break

            for a in data_new:
                # remove conflict inst
                for a_inst in range(a - 4, a + 2):
                    if a_inst in ss and a in ss[a_inst].overlapped_data:
                        if a_inst in self.inst_selected or a_inst in inst_new:
                            logging.debug(
                                "invalid 2 {} {} {} {}: new data conflicts with inst".format(
                                    hex(a_inst),
                                    hex(a),
                                    a_inst in self.inst_selected,
                                    a_inst in inst_new,
                                )
                            )
                            logging.debug(
                                "{} {} ".format(
                                    hex(addr_cur), [hex(x) for x in inst_new]
                                )
                            )
                            is_valid = False
                            break
                        elif a_inst in self.inst_todo:  # and a_inst not in inst_remove:
                            inst_remove.add(a_inst)
                if not is_valid:
                    break

            if not is_valid:
                logging.debug("Invalid {}: data_new conflicts".format(hex(addr_cur)))
                break

            if (
                len(inst_remove.intersection(self.inst_selected)) > 1
                or len(inst_remove.intersection(inst_new)) > 1
                or len(inst_remove.intersection(inst_new_tmp)) > 1
            ):
                is_valid = False
                logging.debug("Invalid {}: inst_remove conflicts".format(hex(addr_cur)))
                break
            inst_remove.intersection_update(self.inst_todo)
            for a in inst_remove:
                for a_d in ss[a].overlapped_data:
                    if a_d in self.data_todo and a_d not in data_new:
                        self.data[a_d].type -= 1
                        data_type_changed.append(a_d)
                        if self.data[a_d].type == 0:
                            data_new_tmp.add(a_d)

            if (
                len(data_remove.intersection(data_new)) > 1
                or len(data_remove.intersection(data_new_tmp)) > 1
                or len(data_remove.intersection(self.data_selected)) > 1
            ):
                # no need as data_remove come from self.data_todo
                logging.debug(f"invalid check")
                logging.debug([hex(a) for a in data_remove.intersection(data_new)])
                logging.debug([hex(a) for a in data_remove.intersection(data_new_tmp)])
                is_valid = False
                break
            data_remove.intersection_update(self.data_todo)

            data_new.intersection_update(self.data_todo)

            self.data_todo.difference_update(data_remove)
            self.data_todo.difference_update(data_new)
            self.data_selected.update(data_new)
            self.inst_todo.difference_update(inst_remove)
            self.inst_todo.difference_update(inst_new)
            self.inst_selected.update(inst_new)

            # for test
            inst_new_total.update(inst_new)
            data_new_total.update(data_new)
            inst_remove_total.update(inst_remove)
            data_remove_total.update(data_remove)

            inst_new = inst_new_tmp
            data_new = data_new_tmp

        if not is_valid:
            for add in data_type_changed:
                self.data[a_d].type += 1

            ## recover
            self.data_todo.update(data_new_total)
            self.data_todo.update(data_remove_total)
            self.data_selected.difference_update(data_new_total)
            self.inst_todo.update(inst_new_total)
            self.inst_todo.update(inst_remove_total)
            self.inst_selected.difference_update(inst_new_total)

            return False

        return is_valid

    def slove_graph(self, ss):
        # logging.info("[+] Slove graph")
        for addr in ss:
            node_inst = ss[addr]
            addr_decode = self.addr_decode(addr)
            for i in range(node_inst.size):
                self.data[addr_decode + i].type += 1
                # TODO: no need to save overlapped data?
                ss[addr].overlapped_data.add(addr_decode + i)

            # compute overlapped inst/data
            for i in range(0, node_inst.size, 2):
                # overlapped ARM inst
                addr_curr = addr_decode + i
                if addr_curr in ss and addr_curr != addr:
                    ss[addr].overlapped_inst.add(addr_curr)
                    ss[addr_curr].overlapped_inst.add(addr)
                # overlapped Thumb inst
                addr_curr = addr_decode + i + 1
                if addr_curr in ss and addr_curr != addr:
                    ss[addr].overlapped_inst.add(addr_curr)
                    ss[addr_curr].overlapped_inst.add(addr)

        self.inst_todo = set([addr for addr in ss.keys()])
        self.inst_selected = set()
        self.data_todo = set(
            [addr for addr in self.data.keys() if self.data[addr].type > 0]
        )
        self.data_selected = set(self.data.keys()) - self.data_todo

        # TODO: check if it is necessary
        ## Initial update
        # data_new = self.data_selected.copy()
        # if not self.greedy_add(set(), data_new, ss, addr):
        #     logging.error("Initial greedy fail")
        # logging.debug("{} {} {}".format(hex(addr), t, s))

        entry_data = [[-self.data[addr].hint, addr, "D"] for addr in self.data_todo]
        entry_inst = [[-ss[addr].hint, addr, ss[addr].type] for addr in self.inst_todo]
        h = entry_data + entry_inst
        heapq.heapify(h)
        # print(h[:3])

        while len(h) > 0:
            s, addr, t = heapq.heappop(h)
            # if s > -0.1:
            if s > -0.01:
                break

            if t == "D":
                if addr not in self.data_todo:
                    continue
                # ignore if the the connected inst is already selected

                data_new = set()
                data_new.add(addr)
                if not self.greedy_add(set(), data_new, ss, addr):
                    logging.debug("Pass data {} {} {}".format(hex(addr), t, s))
                    continue

                logging.debug("{} {} {}".format(hex(addr), t, s))
            else:
                if addr not in self.inst_todo:
                    continue
                addr_reachable = self.dfs_addr_succr_greedy(ss, addr, set())

                inst_new = list()
                is_valid = True
                for a in addr_reachable:
                    if a in self.inst_selected:
                        continue
                    elif a in self.inst_todo:
                        inst_new.append(a)
                    else:
                        is_valid = False
                        break
                if not is_valid:
                    self.inst_todo.remove(addr)
                    logging.debug("Pass inst {} {} {}".format(hex(addr), t, s))
                    continue
                inst_new = set(inst_new)

                if not self.greedy_add(inst_new, set(), ss, addr):
                    logging.debug("Pass inst {} {} {}".format(hex(addr), t, s))
                    continue
                logging.debug("{} {} {}".format(hex(addr), t, s))

        results = [
            [self.addr_decode(addr), ss[addr].type] for addr in self.inst_selected
        ]
        results = sorted(results, key=lambda x: x[0])
        return results

    def print_results(self, results, details=False):
        if len(self.sections) < 1:
            return
        print("Disassemble section (section name, start addr, end addr, size)")
        for sec in self.sections:
            print(
                "  {} {} {} {}".format(
                    sec,
                    hex(self.sections[sec]["start_addr"]),
                    hex(self.sections[sec]["end_addr"]),
                    self.sections[sec]["size"],
                )
            )
        print()

        ss = self.superset_disasm()
        for addr, inst_type in results:
            if inst_type == "T":
                addr = addr + 1
            inst = ss[addr].inst
            if details:
                bytes = "".join(format(x, "02x") for x in inst.bytes)
                print(
                    "{} {} {} {:>8} {} {}".format(
                        hex(self.addr_decode(addr)),
                        inst_type,
                        inst.size,
                        bytes,
                        inst.mnemonic,
                        inst.op_str,
                    )
                )
            else:
                print(
                    "{} {} {}".format(hex(self.addr_decode(addr)), inst_type, inst.size)
                )
        return

    def disassemble(self):
        if len(self.sections) < 1:
            print("No executable section found. Please check the input section name {}".format(self.section_name))
            return

        superset = self.superset_disasm()
        superset = self.update_superset_successor(superset)

        self.initial_data_node(superset)

        superset = self.update_superset_successor_infer(superset)
        superset = self.update_superset_pred(superset)
        self.superset = superset
        # self.print_superset_info(self.superset)

        self.static_analysis(superset)
        # self.save_analysis_hints(superset)
        # self.read_analysis_hints(superset)

        self.compute_node_weights(superset)
        # gc.collect()

        superset = self.update_superset_with_invalid_nodes(superset)
        # ss = pad.release_nodeinst(ss)
        self.superset = superset
        # gc.collect()

        self.aggregate_weights(superset)
        gc.collect()

        results = self.slove_graph(superset)
        # self.print_results(results, self.verbose)
        return results
