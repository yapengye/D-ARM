# This file is part of D-ARM
# Copyright (C) 2023 Yapeng Ye, yapengye@gmail.com
# Copyright (C) 2020 Muhui Jiang, csmjiang@comp.polyu.edu.hk

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

import bisect
import copy
import heapq
import logging
import subprocess

from capstone import *
from capstone.arm import *


class ARMBinary:
    def __init__(self, path, aarch=None, is_stripped=None, section_name=None):
        self.path = path
        self.aarch = aarch
        self.is_stripped = is_stripped
        self.section_name = section_name

        self.code_indexes = []
        self.arm_code_bound = []
        self.arm_codes = []
        self.thumb_code_bound = []
        self.thumb_codes = []
        self.data = []
        self.sections = {}
        self.sections_exec = {}
        self.sections_data = {}
        self.cs_insts = []
        self.data_addr = []

        aarch = self.check_arch()
        if self.aarch is None:
            self.aarch = aarch
            print("The detected arch is {}".format(self.aarch))
        elif self.aarch != aarch:
            logging.warning(
                "Please check the argument -a/-aarch. Provided value is {}, while the detected value is {}.".format(
                    self.aarch, aarch
                )
            )

        if self.is_stripped is None:
            self.is_stripped = self.check_if_stripped()

        if self.section_name is None:
            self.section_name = ".text"

        self.disassembler = BasicDisassembler(aarch=self.aarch)

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
    def to_x_32(s):
        from struct import pack

        if not s:
            return "0"
        x = pack(">i", s)
        while x[0] in ("\0", 0):
            x = x[1:]
        return ARMBinary.to_hex2(x)

    def check_arch(self):
        cmd = "utils/arm-linux-gnueabi-readelf -h " + self.path
        output = subprocess.check_output(cmd, shell=True)
        output = output.decode("ISO-8859-1")

        arch = 32
        for line in output.split("\n"):
            if len(line) == 0:
                continue
            info = line.split(":")
            field = info[0].strip()
            if field == "Class":
                class_info = info[1].strip()
                if class_info == "ELF32":
                    arch = 32
                elif class_info == "ELF64":
                    arch = 64
            elif field == "Machine":
                machine = info[1].strip()
                if machine != "ARM" and machine != "AArch64":
                    logging.warning("Unknown machine type: {}".format(machine))

        return arch

    def check_if_stripped(self):
        cmd = "file {}".format(self.path)
        output = subprocess.check_output(cmd, shell=True)
        output = output.decode("utf-8")
        # print(output)
        if "not stripped" in output:
            return False
        else:
            return True

    def read_sections(self):
        if self.aarch == 32:
            self.read_sections_32()
        elif self.aarch == 64:
            self.read_sections_64()
        else:
            raise RuntimeError("wrong aarch")
                
        return

    def read_symbols(self):
        if self.aarch == 32:
            self.read_symbols_32()
        elif self.aarch == 64:
            self.read_symbols_64()
        else:
            raise RuntimeError("wrong aarch")

    def read_sections_32(self):
        """
        Get the ARM binary's ELF information and where the text section is
        """
        cmd = "utils/arm-linux-gnueabi-readelf -S " + self.path
        output = subprocess.check_output(cmd, shell=True)
        output = output.decode("ISO-8859-1")
        # print(output)
        assert len(output) > 0, "section info should not be empty"
        for line in output.split("\n"):
            text_info = line.strip()[4:].split(" ")
            new_info = []
            for info in text_info:
                if info != "":
                    new_info.append(info)
            if len(new_info) < 7:
                continue
            
            mode_exec, mode_data = False, False
            if "X" in new_info[6]:
                mode_exec = True
            if "W" in new_info[6] or "S" in new_info[6]:
                mode_data = True

            if mode_exec or mode_data:
            # if new_info[0] == ".text":
                addr = int(new_info[2], 16)
                off = int(new_info[3], 16)
                size = int(new_info[4], 16)
                index = int(line.strip()[1:3])
                
                sec_name = new_info[0]
                new_sec = {}
                # new_sec["content"] = f.read(size)
                new_sec["start_addr"] = addr
                new_sec["end_addr"] = addr + size
                new_sec["index"] = index
                new_sec["size"] = size

                if mode_exec:
                    self.sections_exec[sec_name] = new_sec
                if mode_data:
                    self.sections_data[sec_name] = new_sec
                # if new_info[0] == ".text":
                if new_info[0] == self.section_name:
                    self.code_indexes.append(index)
                    f = open(self.path, "rb")
                    f.read(off)
                    new_sec["content"] = f.read(size)
                    f.close()
                    self.sections[sec_name] = new_sec
                # self.sections[sec_name] = {}
                # self.sections[sec_name]["content"] = f.read(size)
                # self.sections[sec_name]["start_addr"] = addr
                # self.sections[sec_name]["end_addr"] = addr + size
                # self.sections[sec_name]["index"] = index
                # self.sections[sec_name]["size"] = size
                logging.debug(
                    f"section name: {sec_name}, start_addr: {addr}, end_addr: {addr + size}, index: {index}"
                )

    def read_symbols_32(self):
        """
        Get the ARM mapping symbols
        """
        # self.is_stripped = True
        cmd = "utils/arm-linux-gnueabi-readelf -s " + self.path
        output = subprocess.check_output(cmd, shell=True)
        output = output.decode("ISO-8859-1")
        # print(output)
        assert len(output) > 0, "mappings symbols should not be empty"
        for line in output.split("\n"):
            if "$a" in line:
                sec_index = int(line.strip().split(" ")[-2])
                if sec_index not in self.code_indexes:
                    continue
                self.arm_code_bound.append(int(line.strip().split(" ")[1], 16))
            if "$d" in line:
                sec_index = int(line.strip().split(" ")[-2])
                if sec_index not in self.code_indexes:
                    continue
                self.data.append(int(line.strip().split(" ")[1], 16))
            if "$t" in line:
                sec_index = int(line.strip().split(" ")[-2])
                if sec_index not in self.code_indexes:
                    continue
                self.thumb_code_bound.append(int(line.strip().split(" ")[1], 16))
            
            # if "Symbol table \'.symtab\'" in line:
            #     self.is_stripped = False
        self.arm_code_bound.sort()
        self.thumb_code_bound.sort()
        self.data.sort()
        self.mappings = sorted(self.arm_code_bound + self.thumb_code_bound + self.data)

    def read_sections_64(self):
        cmd = "utils/aarch64-linux-gnu-readelf -S " + self.path
        output = subprocess.check_output(cmd, shell=True)
        output = output.decode("ISO-8859-1")
        line_list = output.split("\n")
        i = 0
        while i < len(line_list):
            line = line_list[i]
            i += 1
            line = line.strip()
            if len(line) == 0 or not line[0] == "[":
                continue

            new_info = []
            index = line[1:3]
            text_info = line[4:].split(" ")
            for info in text_info:
                if info != "":
                    new_info.append(info)
            line = line_list[i].strip()
            i += 1
            text_info = line.split(" ")
            for info in text_info:
                if info != "":
                    new_info.append(info)
            if len(new_info) < 7:
                continue

            mode_exec, mode_data = False, False
            if "X" in new_info[6]:
                mode_exec = True
            if "W" in new_info[6] or "S" in new_info[6]:
                mode_data = True

            if mode_exec or mode_data:
            # if new_info[0] == ".text":
                addr = int(new_info[2], 16)
                off = int(new_info[3], 16)
                size = int(new_info[4], 16)
                index = int(index)
                
                sec_name = new_info[0]
                new_sec = {}
                # new_sec["content"] = f.read(size)
                new_sec["start_addr"] = addr
                new_sec["end_addr"] = addr + size
                new_sec["index"] = index
                new_sec["size"] = size

                if mode_exec:
                    self.sections_exec[sec_name] = new_sec
                if mode_data:
                    self.sections_data[sec_name] = new_sec
                if new_info[0] == self.section_name:
                # if new_info[0] == ".text":
                    self.code_indexes.append(index)
                    f = open(self.path, "rb")
                    f.read(off)
                    new_sec["content"] = f.read(size)
                    f.close()
                    self.sections[sec_name] = new_sec

                # self.sections[sec_name] = {}
                # self.sections[sec_name]["content"] = f.read(size)
                # self.sections[sec_name]["start_addr"] = addr
                # self.sections[sec_name]["end_addr"] = addr + size
                # self.sections[sec_name]["index"] = index
                # self.sections[sec_name]["size"] = size
                logging.debug(
                    f"section name: {sec_name}, start_addr: {addr}, end_addr: {addr + size}, index: {index}"
                )

    def read_symbols_64(self):
        # self.is_stripped = True
        cmd = "utils/aarch64-linux-gnu-readelf -s " + self.path
        output = subprocess.check_output(cmd, shell=True)
        output = output.decode("ISO-8859-1")
        for line in output.split("\n"):
            if "$x" in line:
                sec_index = int(line.strip().split(" ")[-2])
                if sec_index not in self.code_indexes:
                    continue
                self.arm_code_bound.append(int(line.strip().split(" ")[1], 16))
            if "$d" in line:
                sec_index = int(line.strip().split(" ")[-2])
                if sec_index not in self.code_indexes:
                    continue
                self.data.append(int(line.strip().split(" ")[1], 16))

            # if "Symbol table \'.symtab\'" in line:
            #     self.is_stripped = False
        self.arm_code_bound.sort()
        self.data.sort()
        self.mappings = sorted(self.arm_code_bound + self.data)

    def get_instructions_quick(self):
        """
        Get the binary instructions according to the mapping symbols information
        """
        ## YYP: fix bug len(self.mappings)-1
        set_arm_code_bound, set_thumb_code_bound, set_data = (
            set(self.arm_code_bound),
            set(self.thumb_code_bound),
            set(self.data),
        )
        for i in range(len(self.mappings)):
            for sec in self.sections.keys():
                if self.mappings[i] >= self.sections[sec]["start_addr"]:
                    end_bound = (
                        min(self.mappings[i + 1], self.sections[sec]["end_addr"])
                        if i < len(self.mappings) - 1
                        else self.sections[sec]["end_addr"]
                    )  ## YYP: fixed
                    count_len = 0
                    if self.mappings[i] in set_arm_code_bound:
                        target_text = self.sections[sec]["content"][
                            self.mappings[i]
                            - self.sections[sec]["start_addr"] : end_bound
                            - self.sections[sec]["start_addr"]
                        ]
                        cs_insts = self.disassembler.disasm_arm_inst(
                            target_text, self.mappings[i]
                        )
                        for cs_inst in cs_insts:
                            self.arm_codes.append(cs_inst.address)
                            count_len += cs_inst.size
                        self.cs_insts = self.cs_insts + cs_insts
                        if count_len != len(target_text):
                            # logging.debug("{} {}".format(len(target_text), count_len))
                            logging.debug(
                                "inst error: {} {} {}".format(
                                    self.mappings[i], len(target_text), count_len
                                )
                            )
                    elif self.mappings[i] in set_thumb_code_bound:
                        target_text = self.sections[sec]["content"][
                            self.mappings[i]
                            - self.sections[sec]["start_addr"] : end_bound
                            - self.sections[sec]["start_addr"]
                        ]
                        cs_insts = self.disassembler.disasm_thumb_inst(
                            target_text, self.mappings[i]
                        )
                        for cs_inst in cs_insts:
                            self.thumb_codes.append(cs_inst.address)
                            count_len += cs_inst.size
                        self.cs_insts = self.cs_insts + cs_insts
                        if count_len != len(target_text):
                            # logging.debug("{} {}".format(len(target_text), count_len))
                            logging.debug(
                                "inst error: {} {} {}".format(
                                    self.mappings[i], len(target_text), count_len
                                )
                            )
                    elif self.mappings[i] in set_data:
                        target_text = self.sections[sec]["content"][
                            self.mappings[i]
                            - self.sections[sec]["start_addr"] : end_bound
                            - self.sections[sec]["start_addr"]
                        ]
                        self.data_addr.append(
                            [self.mappings[i], end_bound, target_text]
                        )
                    else:
                        print("Error: unknown mapping addr {}".format(self.mappings[i]))

    def get_instructions(self):
        """
        Get the binary instructions according to the mapping symbols information
        """
        ## YYP: fix bug len(self.mappings)-1
        mappings = copy.deepcopy(self.mappings)
        heapq.heapify(mappings)
        while len(mappings) > 0:
            set_arm_code_bound, set_thumb_code_bound, set_data = (
                set(self.arm_code_bound),
                set(self.thumb_code_bound),
                set(self.data),
            )
            addr = heapq.heappop(mappings)
            for sec in self.sections.keys():
                if addr >= self.sections[sec]["start_addr"]:
                    end_bound = (
                        min(mappings[0], self.sections[sec]["end_addr"])
                        if len(mappings) > 0
                        else self.sections[sec]["end_addr"]
                    )  ## YYP: fixed
                    if addr in set_data:
                        # YYP: moved to get_data
                        continue

                    count_len = 0
                    if addr in set_arm_code_bound:
                        target_text = self.sections[sec]["content"][
                            addr
                            - self.sections[sec]["start_addr"] : end_bound
                            - self.sections[sec]["start_addr"]
                        ]
                        cs_insts = self.disassembler.disasm_arm_inst(target_text, addr)
                        cs_insts_addr = [inst.address for inst in cs_insts]

                        # update missing target
                        redo = False
                        for cs_inst in cs_insts:
                            target, mode = self.check_inst_target(cs_inst, 0)
                            if target < 0:
                                continue
                            elif target > 0 and target < addr:
                                if (mode == 0 and target not in self.arm_codes) or (
                                    mode == 1 and target not in self.thumb_codes
                                ):
                                    print(
                                        "Error disassembly mode contradictory: [{}, {}] {} arm {} {} {}".format(
                                            hex(addr),
                                            hex(end_bound),
                                            hex(target),
                                            hex(cs_inst.address),
                                            cs_inst.mnemonic,
                                            cs_inst.op_str,
                                        )
                                    )
                                if mode == 2 and (
                                    target in self.arm_codes
                                    or target in self.thumb_codes
                                ):
                                    print(
                                        "Error disassembly data contradictory: [{}, {}] {} arm {} {} {}".format(
                                            hex(addr),
                                            hex(end_bound),
                                            hex(target),
                                            hex(cs_inst.address),
                                            cs_inst.mnemonic,
                                            cs_inst.op_str,
                                        )
                                    )

                            elif target > addr and target < end_bound:
                                redo = True
                                heapq.heappush(mappings, target)
                                break
                                # if target not in cs_insts_addr:
                                #    redo = True
                                #    break
                            else:
                                heapq.heappush(mappings, target)
                        if redo:
                            heapq.heappush(mappings, addr)
                            continue

                        for cs_inst in cs_insts:
                            self.arm_codes.append(cs_inst.address)
                            count_len += cs_inst.size
                        self.cs_insts = self.cs_insts + cs_insts
                    elif addr in set_thumb_code_bound:
                        target_text = self.sections[sec]["content"][
                            addr
                            - self.sections[sec]["start_addr"] : end_bound
                            - self.sections[sec]["start_addr"]
                        ]
                        cs_insts = self.disassembler.disasm_thumb_inst(
                            target_text, addr
                        )
                        cs_insts_addr = [inst.address for inst in cs_insts]

                        # update missing target
                        redo = False
                        for cs_inst in cs_insts:
                            target, mode = self.check_inst_target(cs_inst, 1)
                            if target < 0:
                                continue
                            elif target > 0 and target < addr:
                                if (mode == 0 and target not in self.arm_codes) or (
                                    mode == 1 and target not in self.thumb_codes
                                ):
                                    print(
                                        "Error disassembly mode contradictory: [{}, {}] {} thumb {} {} {}".format(
                                            hex(addr),
                                            hex(end_bound),
                                            hex(target),
                                            hex(cs_inst.address),
                                            cs_inst.mnemonic,
                                            cs_inst.op_str,
                                        )
                                    )
                                if mode == 2 and (
                                    target in self.arm_codes
                                    or target in self.thumb_codes
                                ):
                                    print(
                                        "Error disassembly data contradictory: [{}, {}] {} thumb {} {} {}".format(
                                            hex(addr),
                                            hex(end_bound),
                                            hex(target),
                                            hex(cs_inst.address),
                                            cs_inst.mnemonic,
                                            cs_inst.op_str,
                                        )
                                    )
                            elif target > addr and target < end_bound:
                                redo = True
                                heapq.heappush(mappings, target)
                                break
                                # if target not in cs_insts_addr:
                                #    redo = True
                                #    break
                            else:
                                heapq.heappush(mappings, target)
                        if redo:
                            heapq.heappush(mappings, addr)
                            continue

                        for cs_inst in cs_insts:
                            self.thumb_codes.append(cs_inst.address)
                            count_len += cs_inst.size
                        self.cs_insts = self.cs_insts + cs_insts
                    # check error
                    if count_len != len(target_text):
                        logging.debug(
                            "inst error: {} {} {}".format(
                                addr, len(target_text), count_len
                            )
                        )

        # TODO: some data are not included
        self.get_data()

        self.mappings = sorted(self.arm_code_bound + self.thumb_code_bound + self.data)

    # check if the target of the inst is missed in the mapping symbol
    # mode: ARM 0, Thumb 1
    def check_inst_target(self, inst, mode):
        target = -1

        # BRANCH
        if (
            ARM_GRP_BRANCH_RELATIVE in inst.groups
            or ARM_GRP_JUMP in inst.groups
            or ARM_GRP_CALL in inst.groups
        ):
            if len(inst.operands) == 1:
                if inst.operands[0].type == ARM_OP_IMM:
                    target = (
                        int(ARMBinary.to_x_32(inst.operands[0].imm), 16)
                        if inst.operands[0].imm < 0
                        else inst.operands[0].imm
                    )
                    # YYP: fix bx/blx imm successor
                    if inst.id == ARM_INS_BX or inst.id == ARM_INS_BLX:
                        mode = 1 - mode
                elif inst.operands[0].type == ARM_OP_REG:
                    if inst.operands[0].reg == ARM_REG_PC:
                        target = inst.address + 4 if mode == 1 else inst.address + 8
                        mode = 0  # TODO:check
            # YYP: fix cbz/cbnz
            elif len(inst.operands) == 2 and inst.operands[1].type == ARM_OP_IMM:
                target = (
                    int(ARMBinary.to_x_32(inst.operands[1].imm), 16)
                    if inst.operands[1].imm < 0
                    else inst.operands[1].imm
                )

        ## ldr/str xx, [pc, xx]
        if inst.id in [
            ARM_INS_LDRBT,
            ARM_INS_LDRB,
            ARM_INS_LDRD,
            ARM_INS_LDREX,
            ARM_INS_LDREXB,
            ARM_INS_LDREXD,
            ARM_INS_LDREXH,
            ARM_INS_LDRH,
            ARM_INS_LDRHT,
            ARM_INS_LDRSB,
            ARM_INS_LDRSBT,
            ARM_INS_LDRSH,
            ARM_INS_LDRSHT,
            ARM_INS_LDRT,
            ARM_INS_LDR,
        ] or inst.id in [
            ARM_INS_STRBT,
            ARM_INS_STRB,
            ARM_INS_STRD,
            ARM_INS_STREX,
            ARM_INS_STREXB,
            ARM_INS_STREXD,
            ARM_INS_STREXH,
            ARM_INS_STRH,
            ARM_INS_STRHT,
            ARM_INS_STRT,
            ARM_INS_STR,
        ]:
            if len(inst.operands) > 1:
                op = inst.operands[1]
                if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                    if op.mem.index == 0 and op.mem.scale == 1 and op.mem.lshift == 0:
                        if op.mem.base == ARM_REG_PC:
                            target = inst.address + 4 if mode == 1 else inst.address + 8
                            target += op.mem.disp
                            mode = 2
                    else:
                        logging.debug(
                            "LDR/STR: {} {} {} {} {} {}".format(
                                hex(inst.address),
                                op.mem.base,
                                op.mem.index,
                                op.mem.scale,
                                op.mem.disp,
                                op.mem.lshift,
                            )
                        )

        # ignore out-of-bound target
        is_wrong_addr = True
        for sec in self.sections.keys():
            if (
                target >= self.sections[sec]["start_addr"]
                and target <= self.sections[sec]["end_addr"]
            ):
                is_wrong_addr = False
                break
        if is_wrong_addr:
            return -1, mode

        # check if target needs to be added
        index = bisect.bisect_left(self.mappings, target)
        # if it exists
        if index < len(self.mappings) and self.mappings[index] == target:
            return -1, mode
        # TODO: better to always insert. check

        # insert target
        if mode == 0:
            self.arm_code_bound.append(target)
            self.arm_code_bound.sort()
            self.mappings.append(target)
            self.mappings.sort()
        elif mode == 1:
            self.thumb_code_bound.append(target)
            self.thumb_code_bound.sort()
            self.mappings.append(target)
            self.mappings.sort()
        elif mode == 2:
            self.data.append(target)
            self.data.sort()
            self.mappings.append(target)
            self.mappings.sort()

        return target, mode

    def get_data(self):
        inst_size = [(inst.address, inst.size) for inst in self.cs_insts]
        inst_size.sort(key=lambda x: x[0])
        inst_address = [x[0] for x in inst_size]

        sec_sorted = sorted(self.sections.values(), key=lambda x: x["start_addr"])
        for sec in sec_sorted:
            addr = sec["start_addr"]
            i = bisect.bisect_left(inst_address, addr)
            while addr < sec["end_addr"]:
                end_bound = (
                    inst_address[i] if i < len(inst_address) else sec["end_addr"]
                )
                if end_bound - addr > 2:  # DATA
                    target_text = sec["content"][
                        addr - sec["start_addr"] : end_bound - sec["start_addr"]
                    ]
                    self.data_addr.append([addr, end_bound, target_text])
                    if addr not in self.data:
                        logging.info(
                            "new data: {} {}".format(hex(addr), hex(end_bound))
                        )
                addr = (
                    inst_address[i] + inst_size[i][1]
                    if i < len(inst_address)
                    else sec["end_addr"]
                )
                i += 1

        return

    def generate_truth(self, mode_quick=False):
        self.read_sections()
        if len(self.sections) == 0:
            print("No executable section found. Please check the input section name {}".format(self.section_name))
            return
        self.read_symbols()

        # if len(self.mappings) > 0:
        #     self.is_stripped = False
        # else:
        #     self.is_stripped = True

        if mode_quick:
            self.get_instructions_quick()
        else:
            self.get_instructions()
        return

    def get_insts_info(self):
        results = dict()
        set_arm_addr, set_thumb_addr = set(self.arm_codes), set(self.thumb_codes)
        for inst in self.cs_insts:
            addr = inst.address
            if addr in set_arm_addr:
                type = "A"
            elif addr in set_thumb_addr:
                type = "T"
            else:
                print("address error")
            bytes = "".join(format(x, "02x") for x in inst.bytes)
            # print(inst.bytes, binascii.hexlify(inst.bytes), binascii.hexlify(inst.bytes).hex())
            # results[addr] = [type, inst.size, inst.mnemonic, inst.op_str, bytes]
            results[addr] = [type, inst]
        return results

    def print_ground_truth(self, details=False, key_int=False):
        if self.is_stripped:
            print("No ground truth for stripped binary")
            return
        if len(self.sections) == 0:
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

        results = self.get_insts_info()

        for addr in sorted(results.keys()):
            addr_print = addr if key_int else hex(addr)
            # type, inst_size, mnemonic, op_str, bytes = (
            #     results[addr][0],
            #     results[addr][1],
            #     results[addr][2],
            #     results[addr][3],
            #     results[addr][4],
            # )
            type, inst = results[addr]
            bytes = "".join(format(x, "02x") for x in inst.bytes)
            if details:
                print(
                    "{} {} {} {:>8} {} {}".format(
                        addr_print,
                        type,
                        inst.size,
                        bytes,
                        inst.mnemonic,
                        inst.op_str,
                    )
                )
            else:
                print("{} {} {}".format(addr_print, type, inst.size))
                # print("{} {} {}".format(addr_print, results[addr][0], results[addr][1]))
        return


class BasicDisassembler:
    def __init__(self, aarch=32):
        """
        A basic disassembler that uses capstone
        """
        if aarch == 32:
            self.md_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            self.md_arm.detail = True
        elif aarch == 64:
            self.md_arm = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            self.md_arm.detail = True
        else:
            raise RuntimeError("wrong aarch")

        self.md_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.md_thumb.detail = True

    def disasm_arm_inst(self, text, start_addr):
        cs_insts = []
        for insn in self.md_arm.disasm(text, start_addr):
            cs_insts.append(insn)
        return cs_insts

    def disasm_thumb_inst(self, text, start_addr):
        cs_insts = []
        for insn in self.md_thumb.disasm(text, start_addr):
            cs_insts.append(insn)
        return cs_insts


if __name__ == "__main__":
    b = ARMBinary("test/binary/spec2000_gcc5.5_O0_marm_v5t_bzip2", aarch=32) 
    # b = ARMBinary('test/binary/spec2000_gcc5.5_O0_marm_v5t_bzip2_stripped', aarch=32)
    # b.generate_truth()
    b.print_ground_truth(details=False)
