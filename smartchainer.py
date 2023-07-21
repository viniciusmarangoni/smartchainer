#!/usr/bin/env python3
import os
import ast
import cmd
import sys
import copy
import time
import ctypes
import random
import struct
import argparse
import binascii
import traceback
from emulator.x86emulator import x86Instruction, x86Emulator

PENALTY_PER_INSTRUCTION = 1
PENALTY_PER_STACK_MOVEMENT = 1
PENALTY_PER_RETN = 1  # small penalty so retn instructions are not equals to ret
PENALTY_FOR_INSTRUCTION_WITH_OFFSET = 50
PENALTY_FOR_TAINTED_REG = 50
PENALTY_PER_MEMORY_DIFF = 150
PENALTY_PER_STACK_MISALIGN = (PENALTY_PER_MEMORY_DIFF * 4) * 2
PENALTY_GET_STACK_PTR_WITH_EBP = (PENALTY_PER_MEMORY_DIFF * 4) * 2
PENALTY_PER_STACK_TAINT_COLLATERAL = 10000
PENALTY_PER_STACK_MOVEMENT_NEGATIVE = 10000
PENALTY_PER_EXCEPTION = 10000
PENALTY_PER_DIFFERENT_EXCEPTION = 50000
PENALTY_REALLY_HIGH = 5000000

MEM_READ  = 0x1 << 0
MEM_EXEC  = 0x1 << 1
MEM_WRITE = 0x1 << 2

# ZeroReg_chains = {'register-to-zeroe': [Chain, Chain, Chain...]}
ZeroReg_chains = {}

# MoveReg_chains = {'register-src': {'register-dst': [Chain, Chain, Chain...]}}
MoveReg_chains = {}

# LoadConst_chains = {'register-dst': [Chain, Chain, Chain...]}
LoadConst_chains = {}

# LoadConstAuxiliary_chains = {'register-to-modify': {'auxiliary-type': [Chain, Chain, Chain...]}}
LoadConstAuxiliary_chains = {}

# AddReg_chains = {'register-store': {'register-adder or constant': [Chain, Chain, Chain...]}}
AddReg_chains = {}

# SubReg_chains = {'register-store': {'register-subber or constant': [Chain, Chain, Chain...]}}
SubReg_chains = {}

# MemStore_chains = {'mem-addr-register': {'value-register': [Chain, Chain, Chain]}}
MemStore_chains = {}

# MemRead_chains = {'mem-addr-register': {'value-register': [Chain, Chain, Chain]}}
MemRead_chains = {}

# NegReg_chains = {'register-to-neg': [Chain, Chain, Chain...]}
NegReg_chains = {}

# NotReg_chains = {'register-to-not': [Chain, Chain, Chain...]}
NotReg_chains = {}

# GetStackPtr_chains = {'destination-reg': [Chain, Chain, Chain...]}
GetStackPtr_chains = {}

# AddStackPtrConst_chains = {'hex-constant': [Chain, Chain, Chain...]}
AddStackPtrConst_chains = {}

# SubStackPtrConst_chains = {'hex-constant': [Chain, Chain, Chain...]}
SubStackPtrConst_chains = {}

# StackPivot_chains = {'<src-reg | constant>': [Chain, Chain, Chain...]}
StackPivot_chains = {}

tmp_emu = x86Emulator()
KNOWN_REGISTERS_32 = tmp_emu.KNOWN_REGISTERS
tmp_emu = x86Emulator(bits=64)
KNOWN_REGISTERS_64 = tmp_emu.KNOWN_REGISTERS
ALL_KNOWN_REGISTERS = KNOWN_REGISTERS_32 + KNOWN_REGISTERS_64
del tmp_emu

GADGETS_ARCH_BITS = 32
BAD_CHARS = b''


class Chain:
    def __init__(self, gadgets: list):
        self.gadgets = gadgets
        self.grade = 0
        self.tainted_regs = []

        for gadget in gadgets:
            self.grade += gadget.grade
            self.tainted_regs += gadget.tainted_regs

        self.tainted_regs = list(set(self.tainted_regs))
        self.tainted_regs.sort()

    def __str__(self):
        return 'GRADE={0:08d} => {1}'.format(self.grade, [str(x) for x in self.gadgets])
        

class Gadget:
    def __init__(self, address: str, instructions: list, state_transition_info: dict, comments: str='', gadget_type: str='gadget'):
        if gadget_type not in ['gadget', 'constant']:
            raise Exception('Unknown gadget type: {0}'.format(gadget_type))

        self.address = address
        self.instructions = instructions
        self.grade = state_transition_info.get('grade', 0)
        self.tainted_regs = state_transition_info.get('tainted-registers', [])
        self.stack_movement_before_ret = state_transition_info.get('stack-movement-before-ret', 0)
        self.intentional_stack_movement_before_ret = state_transition_info.get('intentional-stack-movement-before-ret', False)
        self.stack_movement_after_ret = state_transition_info.get('stack-movement-after-ret', 0)
        self.comments = comments
        self.gadget_type = gadget_type

    def __str__(self):
        if self.gadget_type == 'gadget':
            return '{0}: {1}'.format(self.address, ' ; '.join(self.instructions))

        elif self.gadget_type == 'constant':
            return '{0}: {1}'.format(self.address, self.comments)

        return '{0}: {1} # {2}'.format(self.address, ' ; '.join(self.instructions), self.comments)


def log_info(msg):
    print(msg)


def address_contains_badchar(address):
    global BAD_CHARS

    if type(address) == str:
        address = parse_integer(address)

    if GADGETS_ARCH_BITS == 64:
        data = struct.pack('<Q', address)

    else:
        data = struct.pack('<I', address)
    
    for bad_char in BAD_CHARS:
        if bad_char in data:
            return True
        
    return False


def filter_gadgets_from_rpplusplus(lines, base_addr=0):
    global GADGETS_ARCH_BITS

    i = 0
    list_length = len(lines)
    ignored_gadgets_count = 0

    while 'A total of ' not in lines[i] and i < list_length:
        if 'Arch: ' in lines[i]:
            index = lines[i].find('Arch: ') + len('Arch: ')
            detected_architecture = lines[i][index:].strip()

            if detected_architecture in ['x86', 'x64']:
                different_arch = False

                if detected_architecture == 'x86' and GADGETS_ARCH_BITS == 64:
                    different_arch = True

                elif detected_architecture == 'x64' and GADGETS_ARCH_BITS == 32:
                    different_arch = True

                if different_arch:
                    print('[!] The specified gadgets file seems to contain instructions for {0} architecture'.format(detected_architecture))
                    answer = input('[?] Modify the architecture to {0}? [Y/n]: '.format(detected_architecture))

                    if answer.upper() in ['Y', '']:
                        if detected_architecture == 'x86':
                            GADGETS_ARCH_BITS = 32

                        elif detected_architecture == 'x64':
                            GADGETS_ARCH_BITS = 64

                        log_info('[+] Architecture set to {0}'.format(detected_architecture))

        i += 1

    i += 1
    if i >= list_length:
        return None

    gadgets = []
    lines = lines[i:]

    for line in lines:
        sep = line.find(':')

        if sep == -1:
            continue

        address = line[:sep].strip()
        instructions = line[sep+1:].strip().split(';')

        if 'found' in instructions[-1]:
            instructions = instructions[:-1]

        instructions = list(map(lambda x: x.strip(), instructions))

        address = parse_integer(address)
        if base_addr != 0:
            address += base_addr

        if GADGETS_ARCH_BITS == 64:
            address = '{0:#018x}'.format(address)

        else:
            address = '{0:#010x}'.format(address)

        if not address_contains_badchar(address):
            gadgets.append({'address': address, 'instructions': instructions})

        else:
            ignored_gadgets_count += 1

    if ignored_gadgets_count != 0:
        log_info('[+] Ignored {0} gadgets because of bad chars'.format(ignored_gadgets_count))

    return gadgets


def remove_duplicated_gadgets(gadgets):
    instruction_dictionary = {}
    new_gadgets = []
    length = len(gadgets)

    for i, gadget in enumerate(gadgets):
        sys.stdout.write('\r[+] Removing duplicated gadgets... {0:03d}%'.format(int(((i+1) / length) * 100)))
        sys.stdout.flush()

        dictionary_key = str(gadget['instructions'])
        if instruction_dictionary.get(dictionary_key, None) == None:
            instruction_dictionary[dictionary_key] = 1
            new_gadgets.append(gadget)

        else:
            instruction_dictionary[dictionary_key] += 1

    sys.stdout.write('\n')
    sys.stdout.flush()

    return new_gadgets

def get_gadgets_from_file(filename, base_addr: int=0):
    global BAD_CHARS

    log_info('[+] Loading gadgets from {0}...'.format(filename))

    if BAD_CHARS:
        log_info('[+] Bad Chars: {0}'.format(bytes_to_hex_escaped(BAD_CHARS)))

    if base_addr != 0:
        log_info('[+] Rebase gadgets: {0}'.format(hex(base_addr)))

    f = open(filename, 'r')
    data = f.read()
    f.close()

    data = data.replace('\r\n', '\n').split('\n')
    gadgets = filter_gadgets_from_rpplusplus(data, base_addr)

    return gadgets

def get_emulator_state(emu):
    if emu.BITS == 64:
        registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rbp', 'rsp']

    else:
        registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp']

    state = {
        'bits': emu.BITS,
        'registers': {},
        'exceptions': copy.deepcopy(emu.exceptions),
        'different_exceptions_count': emu.different_exceptions_count,
        'total_exceptions_count': emu.total_exceptions_count,
        'memory': copy.deepcopy(emu.memory),
        'memory-write-count': emu.memory_write_count,
        'memory-write-list': emu.memory_write_list
    }

    for reg in registers:
        state['registers'][reg] = emu.get_register_value(reg)

    return state


def execute_gadget(emu, instructions):
    for instruction in instructions:
        emu.exec_instruction(x86Instruction(instruction))

    return emu


def memory_num_diff_bytes(memory1, memory2, memory_write_list, mem_taint_exceptions=[], max_diff_bytes=None):
    count = 0

    for mem_write_item in memory_write_list:
        # {'page': page, 'offset': offset, 'byte': b}
        page = mem_write_item['page']
        offset = mem_write_item['offset']

        effective_addr = page | offset
        if effective_addr in mem_taint_exceptions:
            continue

        try:
            if memory1[page][offset] != memory2[page][offset]:
                count += 1

        except Exception as e:
            count += 1

    return count


def get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[], mem_taint_exceptions=[], additional_penalty=0, stack_pivoted=False):
    grade =  PENALTY_PER_INSTRUCTION * len(instructions)
    grade += additional_penalty
    grade += PENALTY_PER_DIFFERENT_EXCEPTION * new_state['different_exceptions_count']
    grade += PENALTY_PER_EXCEPTION * new_state['total_exceptions_count']
    diff_bytes = memory_num_diff_bytes(initial_state['memory'], new_state['memory'], new_state['memory-write-list'], mem_taint_exceptions=mem_taint_exceptions)

    grade += PENALTY_PER_MEMORY_DIFF * diff_bytes
    reg_taint_count = 0
    tainted_regs = []

    registers = list(initial_state['registers'].keys())
    for reg in registers:
        if reg not in ['rsp', 'esp'] and reg not in taint_exceptions:
            if new_state['registers'][reg] != initial_state['registers'][reg]:
                reg_taint_count += 1
                tainted_regs.append(reg)

        if stack_pivoted and reg in ['rsp', 'esp']:
            if reg not in taint_exceptions:
                reg_taint_count += 1
                tainted_regs.append(reg)

                grade += PENALTY_PER_STACK_TAINT_COLLATERAL

    grade += PENALTY_FOR_TAINTED_REG * reg_taint_count
    
    info = {}
    info['stack-movement-before-ret'] = 0
    info['stack-movement-after-ret'] = 0

    if initial_state['bits'] == 64:
        stack_movement = new_state['registers']['rsp'] - initial_state['registers']['rsp']

    else:
        stack_movement = new_state['registers']['esp'] - initial_state['registers']['esp']

    if stack_movement < 0:
        if 'esp' not in taint_exceptions and 'rsp' not in taint_exceptions:
            grade += PENALTY_PER_STACK_MOVEMENT_NEGATIVE * (stack_movement * -1)

    else:
        if 'esp' not in taint_exceptions and 'rsp' not in taint_exceptions:
            grade += PENALTY_PER_STACK_MOVEMENT * stack_movement

    try:
        ret_instr = x86Instruction(instructions[-1])
        if ret_instr.mnemonic == 'ret':
            info['stack-movement-after-ret'] = 0
            info['stack-movement-before-ret'] = stack_movement - info['stack-movement-after-ret']

        elif ret_instr.mnemonic == 'retn':
            grade += PENALTY_PER_RETN
            if ret_instr.first_operand.startswith('0x'):
                stack_movement_after_ret = int(ret_instr.first_operand, 16)

            elif ret_instr.first_operand.isdigit():
                stack_movement_after_ret = int(ret_instr.first_operand)

            else:
                raise Exception('Unknown operand')

            info['stack-movement-after-ret'] = stack_movement_after_ret
            info['stack-movement-before-ret'] = stack_movement - info['stack-movement-after-ret']

        else:
            info['stack-movement-after-ret'] = 0
            info['stack-movement-before-ret'] = stack_movement - info['stack-movement-after-ret']

    except Exception as e:
        print(e)

    stack_alignment = 4
    if initial_state['bits'] == 64:
        stack_alignment = 8

    if info['stack-movement-after-ret'] % stack_alignment != 0:
        grade += PENALTY_PER_STACK_MISALIGN

    info['grade'] = grade
    info['tainted-registers'] = tainted_regs

    return info


def add_to_LoadConstAuxiliary(reg: str, auxiliary_type:str, chain: Chain):
    global LoadConstAuxiliary_chains

    if LoadConstAuxiliary_chains.get(reg, None) == None:
        LoadConstAuxiliary_chains[reg] = {}

    if LoadConstAuxiliary_chains[reg].get(auxiliary_type, None) == None:
        LoadConstAuxiliary_chains[reg][auxiliary_type] = []

    LoadConstAuxiliary_chains[reg][auxiliary_type].append(chain)


def add_to_ZeroReg(reg: str, chain: Chain):
    global ZeroReg_chains

    if ZeroReg_chains.get(reg, None) == None:
        ZeroReg_chains[reg] = []

    ZeroReg_chains[reg].append(chain)


def add_to_NegReg(reg: str, chain: Chain):
    global NegReg_chains

    if NegReg_chains.get(reg, None) == None:
        NegReg_chains[reg] = []

    NegReg_chains[reg].append(chain)


def add_to_NotReg(reg: str, chain: Chain):
    global NotReg_chains

    if NotReg_chains.get(reg, None) == None:
        NotReg_chains[reg] = []

    NotReg_chains[reg].append(chain)


def add_to_SubStackPtrConst(constant: str, chain: Chain):
    global SubStackPtrConst_chains

    if SubStackPtrConst_chains.get(constant, None) == None:
        SubStackPtrConst_chains[constant] = []

    SubStackPtrConst_chains[constant].append(chain)


def add_to_AddStackPtrConst(constant: str, chain: Chain):
    global AddStackPtrConst_chains

    if AddStackPtrConst_chains.get(constant, None) == None:
        AddStackPtrConst_chains[constant] = []

    AddStackPtrConst_chains[constant].append(chain)


def analyze_for_SubStackPtrConst(gadget):
    instructions = gadget['instructions']
    address = gadget['address']
    first_instr = x86Instruction(instructions[0])

    def SubStackPtrConst_finish_analysis():
        emu = x86Emulator(bits=GADGETS_ARCH_BITS)
        emu.map_new_stack_on_map_error(True)

        initial_state = get_emulator_state(emu)
        emu = execute_gadget(emu, instructions)
        new_state = get_emulator_state(emu)

        if GADGETS_ARCH_BITS == 64:
            stack_ptr = 'rsp'

        else:
            stack_ptr = 'esp'

        state_transition_info = get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[stack_ptr], stack_pivoted=True)
        state_transition_info['intentional-stack-movement-before-ret'] = True
        constant = state_transition_info['stack-movement-before-ret']

        if GADGETS_ARCH_BITS == 64:
            ret_movement = 8

        else:
            ret_movement = 4

        constant = abs(constant + ret_movement)

        if constant > 0:
            add_to_SubStackPtrConst(hex(constant), Chain([Gadget(address, instructions, state_transition_info)]))

    if first_instr.mnemonic == 'sub' and first_instr.first_operand in ['esp', 'rsp']:
        if first_instr.second_operand.startswith('0x') or first_instr.second_operand.isdigit():
            last_instr = x86Instruction(instructions[-1])
            if last_instr.mnemonic in ['ret', 'retn']:
                SubStackPtrConst_finish_analysis()


def analyze_for_AddStackPtrConst(gadget):
    instructions = gadget['instructions']
    address = gadget['address']
    first_instr = x86Instruction(instructions[0])

    def AddStackPtrConst_finish_analysis():
        emu = x86Emulator(bits=GADGETS_ARCH_BITS)
        emu.map_new_stack_on_map_error(True)

        initial_state = get_emulator_state(emu)
        emu = execute_gadget(emu, instructions)
        new_state = get_emulator_state(emu)

        if GADGETS_ARCH_BITS == 64:
            stack_ptr = 'rsp'

        else:
            stack_ptr = 'esp'

        state_transition_info = get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[stack_ptr], stack_pivoted=True)
        state_transition_info['intentional-stack-movement-before-ret'] = True
        constant = state_transition_info['stack-movement-before-ret']

        if GADGETS_ARCH_BITS == 64:
            ret_movement = 8

        else:
            ret_movement = 4

        constant = constant - ret_movement

        if constant > 0:
            add_to_AddStackPtrConst(hex(constant), Chain([Gadget(address, instructions, state_transition_info)]))

    if first_instr.mnemonic == 'add' and first_instr.first_operand in ['esp', 'rsp']:
        if first_instr.second_operand.startswith('0x') or first_instr.second_operand.isdigit():
            last_instr = x86Instruction(instructions[-1])
            if last_instr.mnemonic in ['ret', 'retn']:
                AddStackPtrConst_finish_analysis()


def analyze_for_NegReg(gadget):
    instructions = gadget['instructions']
    address = gadget['address']
    first_instr = x86Instruction(instructions[0])

    def NegReg_finish_analysis():
        emu = x86Emulator(bits=GADGETS_ARCH_BITS)

        if emu.BITS == 64:
            initial_value = 0xc0c1c2c3c4c5c6c7
            expected_value = 0x3f3e3d3c3b3a3939

        else:
            initial_value = 0xc0c1c2c3
            expected_value = 0x3f3e3d3d

        emu.set_register_value(first_instr.first_operand, initial_value)
        initial_state = get_emulator_state(emu)
        emu = execute_gadget(emu, instructions)

        if emu.get_register_value(first_instr.first_operand) == expected_value:
            new_state = get_emulator_state(emu)
            state_transition_info = get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[first_instr.first_operand])
            grade = state_transition_info['grade']
            tainted_regs = state_transition_info['tainted-registers']

            add_to_NegReg(first_instr.first_operand, Chain([Gadget(address, instructions, state_transition_info)]))

    if first_instr.mnemonic == 'neg' and first_instr.first_operand in ALL_KNOWN_REGISTERS:
        NegReg_finish_analysis()


def analyze_for_NotReg(gadget):
    instructions = gadget['instructions']
    address = gadget['address']
    first_instr = x86Instruction(instructions[0])

    def NotReg_finish_analysis():
        emu = x86Emulator(bits=GADGETS_ARCH_BITS)

        if emu.BITS == 64:
            initial_value = 0xc0c1c2c3c4c5c6c7
            expected_value = 0x3f3e3d3c3b3a3938

        else:
            initial_value = 0xc0c1c2c3
            expected_value = 0x3f3e3d3c

        emu.set_register_value(first_instr.first_operand, initial_value)
        initial_state = get_emulator_state(emu)
        emu = execute_gadget(emu, instructions)

        if emu.get_register_value(first_instr.first_operand) == expected_value:
            new_state = get_emulator_state(emu)
            state_transition_info = get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[first_instr.first_operand])
            grade = state_transition_info['grade']
            tainted_regs = state_transition_info['tainted-registers']

            add_to_NotReg(first_instr.first_operand, Chain([Gadget(address, instructions, state_transition_info)]))

    if first_instr.mnemonic == 'not' and first_instr.first_operand in ALL_KNOWN_REGISTERS:
        NotReg_finish_analysis()


def analyze_for_ZeroReg(gadget):
    instructions = gadget['instructions']
    address = gadget['address']
    first_instr = x86Instruction(instructions[0])

    def ZeroReg_finish_analysis():
        emu = x86Emulator(bits=GADGETS_ARCH_BITS)
        initial_state = get_emulator_state(emu)
        emu = execute_gadget(emu, instructions)

        if emu.get_register_value(first_instr.first_operand) == 0:
            new_state = get_emulator_state(emu)
            state_transition_info = get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[first_instr.first_operand])
            grade = state_transition_info['grade']
            tainted_regs = state_transition_info['tainted-registers']

            add_to_ZeroReg(first_instr.first_operand, Chain([Gadget(address, instructions, state_transition_info)]))


    if first_instr.mnemonic == 'xor' and first_instr.first_operand == first_instr.second_operand:
        ZeroReg_finish_analysis()
        

    elif first_instr.mnemonic == 'sub' and first_instr.first_operand == first_instr.second_operand:
        ZeroReg_finish_analysis()

    elif first_instr.mnemonic in ['mov', 'and'] and first_instr.first_operand in ALL_KNOWN_REGISTERS:
        value = first_instr.second_operand
        if value.startswith('0x'):
            value = int(value, 16)
            if value == 0:
                ZeroReg_finish_analysis()


def add_to_MoveReg(src_reg: str, dst_reg, chain: Chain):
    global MoveReg_chains

    if MoveReg_chains.get(src_reg, None) == None:
        MoveReg_chains[src_reg] = {}

    if MoveReg_chains[src_reg].get(dst_reg, None) == None:
        MoveReg_chains[src_reg][dst_reg] = []

    MoveReg_chains[src_reg][dst_reg].append(chain)


def analyze_for_MovReg(gadget):
    instructions = gadget['instructions']
    address = gadget['address']
    first_instr = x86Instruction(instructions[0])
    stack_pivoted = False

    def discover_moves(initial_state, new_state, potential_stack_pivot=False):
        nonlocal stack_pivoted
        stack_pivoted = False

        moves = []
        regs = list(initial_state['registers'].keys())

        for src in regs:
            regs_except_src = list(regs)
            regs_except_src.remove(src)

            src_value = initial_state['registers'][src]

            for dst in regs_except_src:
                if potential_stack_pivot:
                    if new_state['registers'][dst] & 0xfffffffffffff000 == src_value & 0xfffffffffffff000:
                        moves.append({'src': src, 'dst': dst})

                        if dst in ['esp', 'rsp']:
                            stack_pivoted = True

                else:
                    if new_state['registers'][dst] == src_value:
                        moves.append({'src': src, 'dst': dst})

        return moves

    def MovReg_finish_analysis(potential_stack_pivot=False):
        emu = x86Emulator(bits=GADGETS_ARCH_BITS)

        if potential_stack_pivot:
            emu.fail_mem_op_far_from_sp(True)

            if GADGETS_ARCH_BITS == 64:
                emu.set_register_value('rbp', 0xf0f1f2f3f4f5f6f7)
                # except rsp
                registers_except_stack = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rbp']

            else:
                emu.set_register_value('ebp', 0x70717273)

                # except esp
                registers_except_stack = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']

            for reg in registers_except_stack:
                original_value = emu.get_register_value(reg)
                pages_to_map = [original_value - 0x1000, original_value, original_value + 0x1000]

                for page in pages_to_map:
                    # we can send an address instead of a page, since the emu.map_page will
                    # truncate the address to a page address automatically
                    emu.map_page(page, MEM_READ | MEM_WRITE)

        initial_state = get_emulator_state(emu)
        emu = execute_gadget(emu, instructions)

        new_state = get_emulator_state(emu)
        moves = discover_moves(initial_state, new_state, potential_stack_pivot=potential_stack_pivot)
        
        for move in moves:
            state_transition_info = get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[move['dst']], stack_pivoted=stack_pivoted)
            
            grade = state_transition_info['grade']
            tainted_regs = state_transition_info['tainted-registers']

            if move['dst'] in ['esp', 'rsp']:
                state_transition_info['intentional-stack-movement-before-ret'] = True

            add_to_MoveReg(move['src'], move['dst'], Chain([Gadget(address, instructions, state_transition_info)]))

    if first_instr.mnemonic == 'mov' and first_instr.first_operand in ALL_KNOWN_REGISTERS and first_instr.second_operand in ALL_KNOWN_REGISTERS:
        if first_instr.first_operand in ['esp', 'rsp']:
            MovReg_finish_analysis(potential_stack_pivot=True)

        else:
            MovReg_finish_analysis()

    elif first_instr.mnemonic == 'xchg' and first_instr.first_operand in ALL_KNOWN_REGISTERS and first_instr.second_operand in ALL_KNOWN_REGISTERS:
        if first_instr.first_operand != first_instr.second_operand:
            if first_instr.first_operand in ['esp', 'rsp'] or first_instr.second_operand in ['esp', 'rsp']:
                MovReg_finish_analysis(potential_stack_pivot=True)

            else:
                MovReg_finish_analysis()

    elif first_instr.mnemonic == 'push' and first_instr.first_operand in ALL_KNOWN_REGISTERS:
            MovReg_finish_analysis()

    elif first_instr.mnemonic == 'lea' and first_instr.first_operand in ALL_KNOWN_REGISTERS:
        if '[' in first_instr.second_operand:
            if '[esp]' in first_instr.second_operand or '[rsp]' in first_instr.second_operand:
                MovReg_finish_analysis(potential_stack_pivot=True)

            else:
                MovReg_finish_analysis()


def add_to_LoadConst(dst_reg: str, chain: Chain):
    global LoadConst_chains

    if LoadConst_chains.get(dst_reg, None) == None:
        LoadConst_chains[dst_reg] = []

    LoadConst_chains[dst_reg].append(chain)


def analyze_for_LoadConst(gadget):
    instructions = gadget['instructions']
    address = gadget['address']
    first_instr = x86Instruction(instructions[0])

    def LoadConst_finish_analysis():
        emu = x86Emulator(bits=GADGETS_ARCH_BITS)
        stack_ptr = emu.get_stack_pointer_value()
        
        if emu.BITS == 64:
            magic = 0xc0c1c2c3c4c5c6c7
            emu.write_mem(stack_ptr, struct.pack('<Q', magic))

        else:
            magic = 0xc0c1c2c3
            emu.write_mem(stack_ptr, struct.pack('<I', magic))

        initial_state = get_emulator_state(emu)
        emu = execute_gadget(emu, instructions)

        if emu.get_register_value(first_instr.first_operand) == magic:
            new_state = get_emulator_state(emu)
            state_transition_info = get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[first_instr.first_operand])
            grade = state_transition_info['grade']
            tainted_regs = state_transition_info['tainted-registers']

            add_to_LoadConst(first_instr.first_operand, Chain([Gadget(address, instructions, state_transition_info)]))


    if first_instr.mnemonic == 'pop' and first_instr.first_operand in ALL_KNOWN_REGISTERS:
        LoadConst_finish_analysis()


def add_to_AddReg(reg_store: str, reg_adder: str, chain: Chain):
    global AddReg_chains

    if AddReg_chains.get(reg_store, None) == None:
        AddReg_chains[reg_store] = {}

    if AddReg_chains[reg_store].get(reg_adder, None) == None:
        AddReg_chains[reg_store][reg_adder] = []

    AddReg_chains[reg_store][reg_adder].append(chain)


def analyze_for_AddReg(gadget):
    instructions = gadget['instructions']
    address = gadget['address']
    first_instr = x86Instruction(instructions[0])
    result_reg = None
    adder_reg = None
    stack_pivoted = False

    def AddReg_finish_analysis_const():
        emu = x86Emulator(bits=GADGETS_ARCH_BITS)

        if emu.BITS == 64:
            start_reg_value = 0x1122334455667788
            value_to_add = adder_reg  # is not a register, actually - is a constant
            expected_value = start_reg_value + value_to_add

        else:
            start_reg_value = 0x11223344
            value_to_add = adder_reg  # is not a register, actually - is a constant
            expected_value = start_reg_value + value_to_add

        emu.set_register_value(result_reg, start_reg_value)

        initial_state = get_emulator_state(emu)
        emu = execute_gadget(emu, instructions)

        satisfied_condition = emu.get_register_value(result_reg) == expected_value

        if satisfied_condition:
            new_state = get_emulator_state(emu)
            state_transition_info = get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[result_reg])
            grade = state_transition_info['grade']
            tainted_regs = state_transition_info['tainted-registers']

            add_to_AddReg(result_reg, hex(adder_reg), Chain([Gadget(address, instructions, state_transition_info)]))

    def AddReg_finish_analysis(potential_stack_pivot=False):
        nonlocal stack_pivoted

        emu = x86Emulator(bits=GADGETS_ARCH_BITS)

        if emu.BITS == 64:
            start_reg_value = 0x1122334455667788
            value_to_add = 0x1234123412341234
            expected_value = start_reg_value + value_to_add

        else:
            start_reg_value = 0x11223344
            value_to_add = 0x12341234
            expected_value = start_reg_value + value_to_add

        if potential_stack_pivot:
            emu.fail_mem_op_far_from_sp(True)
            start_reg_value = emu.get_stack_pointer_value()
            expected_value = start_reg_value + value_to_add
            emu.set_register_value(adder_reg, value_to_add)

            pages_to_map = [expected_value - 0x1000, expected_value, expected_value + 0x1000]
            pages_to_map = list(map(lambda x: x & 0xfffffffffffff000, pages_to_map))

            for page in pages_to_map:
                emu.map_page(page, MEM_READ | MEM_WRITE)

        else:
            emu.set_register_value(result_reg, start_reg_value)
            emu.set_register_value(adder_reg, value_to_add)

        initial_state = get_emulator_state(emu)
        emu = execute_gadget(emu, instructions)

        satisfied_condition = False

        if potential_stack_pivot:
            result_stack_ptr = emu.get_stack_pointer_value()
            satisfied_condition = (result_stack_ptr & 0xfffffffffffff000 ) in pages_to_map

            if satisfied_condition:
                stack_pivoted = True

        else:
            satisfied_condition = emu.get_register_value(result_reg) == expected_value

        if satisfied_condition:
            new_state = get_emulator_state(emu)
            state_transition_info = get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[result_reg], stack_pivoted=stack_pivoted)
            grade = state_transition_info['grade']
            tainted_regs = state_transition_info['tainted-registers']

            add_to_AddReg(result_reg, adder_reg, Chain([Gadget(address, instructions, state_transition_info)]))


    if first_instr.mnemonic == 'add' and first_instr.first_operand in ALL_KNOWN_REGISTERS and first_instr.second_operand in ALL_KNOWN_REGISTERS:
        result_reg = first_instr.first_operand
        adder_reg = first_instr.second_operand

        if first_instr.first_operand in ['esp', 'rsp']:
            AddReg_finish_analysis(potential_stack_pivot=True)

        else:
            AddReg_finish_analysis()

    elif first_instr.mnemonic == 'add' and first_instr.first_operand in ALL_KNOWN_REGISTERS:
        if first_instr.first_operand not in ['esp', 'rsp']:
            if first_instr.second_operand.startswith('0x') or first_instr.second_operand.isdigit():
                result_reg = first_instr.first_operand

                try:
                    adder_reg = first_instr.second_operand
                    if adder_reg.startswith('0x'):
                        adder_reg = int(adder_reg, 16)

                    else:
                        adder_reg = int(adder_reg)

                    AddReg_finish_analysis_const()

                except:
                    pass

    elif first_instr.mnemonic == 'inc' and first_instr.first_operand in ALL_KNOWN_REGISTERS:
        if first_instr.first_operand not in ['esp', 'rsp']:

            result_reg = first_instr.first_operand
            adder_reg = 0x1
            AddReg_finish_analysis_const()

    elif first_instr.mnemonic == 'lea' and first_instr.first_operand in ALL_KNOWN_REGISTERS:
        if '[' in first_instr.second_operand:
            i = first_instr.second_operand.find('[')
            j = first_instr.second_operand.find(']')
            sum_sign_count = first_instr.second_operand.count('+')

            if i != -1 and j != -1 and sum_sign_count == 1:
                text = first_instr.second_operand[i+1:j]
                items = text.split('+')

                if len(items) == 2:
                    if items[0] in ALL_KNOWN_REGISTERS and items[1] in ALL_KNOWN_REGISTERS and items[0] != items[1]:
                        if first_instr.first_operand in items:
                            result_reg = first_instr.first_operand

                            if first_instr.first_operand == items[0]:
                                adder_reg = items[1]

                            else:
                                adder_reg = items[0]

                            if result_reg in ['esp', 'rsp']:
                                AddReg_finish_analysis(potential_stack_pivot=True)

                            else:
                                AddReg_finish_analysis()


def add_to_SubReg(reg_store: str, reg_subber: str, chain: Chain):
    global SubReg_chains

    if SubReg_chains.get(reg_store, None) == None:
        SubReg_chains[reg_store] = {}

    if SubReg_chains[reg_store].get(reg_subber, None) == None:
        SubReg_chains[reg_store][reg_subber] = []

    SubReg_chains[reg_store][reg_subber].append(chain)


def analyze_for_SubReg(gadget):
    instructions = gadget['instructions']
    address = gadget['address']
    first_instr = x86Instruction(instructions[0])
    result_reg = None
    subber_reg = None
    stack_pivoted = False

    def SubReg_finish_analysis_const():
        emu = x86Emulator(bits=GADGETS_ARCH_BITS)

        if emu.BITS == 64:
            start_reg_value = 0x23564578679a89bc
            value_to_sub = subber_reg  # is not a register, actually - is a constant
            expected_value = start_reg_value - value_to_sub

        else:
            start_reg_value = 0x23564578
            value_to_sub = subber_reg  # is not a register, actually - is a constant
            expected_value = start_reg_value - value_to_sub

        emu.set_register_value(result_reg, start_reg_value)

        initial_state = get_emulator_state(emu)
        emu = execute_gadget(emu, instructions)

        satisfied_condition = emu.get_register_value(result_reg) == expected_value

        if satisfied_condition:
            new_state = get_emulator_state(emu)
            state_transition_info = get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[result_reg], stack_pivoted=stack_pivoted)
            grade = state_transition_info['grade']
            tainted_regs = state_transition_info['tainted-registers']

            add_to_SubReg(result_reg, hex(subber_reg), Chain([Gadget(address, instructions, state_transition_info)]))

    def SubReg_finish_analysis(potential_stack_pivot=False):
        nonlocal stack_pivoted

        emu = x86Emulator(bits=GADGETS_ARCH_BITS)

        if emu.BITS == 64:
            start_reg_value = 0x23564578679a89bc
            value_to_sub = 0x1234123412341234
            expected_value = start_reg_value - value_to_sub

        else:
            start_reg_value = 0x23564578
            value_to_sub = 0x12341234
            expected_value = start_reg_value - value_to_sub

        if potential_stack_pivot:
            emu.fail_mem_op_far_from_sp(True)
            start_reg_value = emu.get_stack_pointer_value()
            expected_value = start_reg_value - value_to_sub
            emu.set_register_value(subber_reg, value_to_sub)

            pages_to_map = [expected_value - 0x1000, expected_value, expected_value + 0x1000]
            pages_to_map = list(map(lambda x: x & 0xfffffffffffff000, pages_to_map))

            for page in pages_to_map:
                emu.map_page(page, MEM_READ | MEM_WRITE)

        else:
            emu.set_register_value(result_reg, start_reg_value)
            emu.set_register_value(subber_reg, value_to_sub)

        initial_state = get_emulator_state(emu)
        emu = execute_gadget(emu, instructions)

        satisfied_condition = False

        if potential_stack_pivot:
            result_stack_ptr = emu.get_stack_pointer_value()
            satisfied_condition = (result_stack_ptr & 0xfffffffffffff000 ) in pages_to_map

            if satisfied_condition:
                stack_pivoted = True

        else:
            satisfied_condition = emu.get_register_value(result_reg) == expected_value

        if satisfied_condition:
            new_state = get_emulator_state(emu)
            state_transition_info = get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[result_reg], stack_pivoted=stack_pivoted)
            grade = state_transition_info['grade']
            tainted_regs = state_transition_info['tainted-registers']

            add_to_SubReg(result_reg, subber_reg, Chain([Gadget(address, instructions, state_transition_info)]))


    if first_instr.mnemonic == 'sub' and first_instr.first_operand in ALL_KNOWN_REGISTERS and first_instr.second_operand in ALL_KNOWN_REGISTERS:
        result_reg = first_instr.first_operand
        subber_reg = first_instr.second_operand
        
        if result_reg in ['esp', 'rsp']:
            print(instructions)
            SubReg_finish_analysis(potential_stack_pivot=True)

        else:
            SubReg_finish_analysis()

    elif first_instr.mnemonic == 'sub' and first_instr.first_operand in ALL_KNOWN_REGISTERS:
        if first_instr.first_operand not in ['esp', 'rsp']:
            if first_instr.second_operand.startswith('0x') or first_instr.second_operand.isdigit():
                result_reg = first_instr.first_operand

                try:
                    subber_reg = first_instr.second_operand
                    if subber_reg.startswith('0x'):
                        subber_reg = int(subber_reg, 16)

                    else:
                        subber_reg = int(subber_reg)

                    SubReg_finish_analysis_const()

                except:
                    pass

    elif first_instr.mnemonic == 'dec' and first_instr.first_operand in ALL_KNOWN_REGISTERS:
        if first_instr.first_operand not in ['esp', 'rsp']:
            result_reg = first_instr.first_operand
            subber_reg = 0x1

            SubReg_finish_analysis_const()

def add_to_MemStore(mem_addr_reg: str, value_reg: str, chain: Chain):
    global MemStore_chains

    if MemStore_chains.get(mem_addr_reg, None) == None:
        MemStore_chains[mem_addr_reg] = {}

    if MemStore_chains[mem_addr_reg].get(value_reg, None) == None:
        MemStore_chains[mem_addr_reg][value_reg] = []

    MemStore_chains[mem_addr_reg][value_reg].append(chain)


def get_register_and_offset_from_memory_operation(operation):
    i = operation.find('[')
    j = operation.find(']')

    if i == -1 or j == -1:
        return None, None

    operation = operation[i+1:j]

    if operation in ALL_KNOWN_REGISTERS:
        register = operation
        offset = 0
        return register, offset

    if operation.count('*') > 0 or operation.count('+') > 1 or operation.count('-') > 1:
        return None, None

    if operation.count('+') == 0 and operation.count('-') == 0:
        return None, None

    sep = None
    if operation.count('+') == 1 and operation.count('-') == 0:
        sep = '+'

    elif operation.count('+') == 0 and operation.count('-') == 1:
        sep = '-'

    else:
        return None, None

    register, offset = operation.split(sep)

    if register not in ALL_KNOWN_REGISTERS:
        return None, None

    if offset.startswith('0x'):
        try:
            offset = int(offset, 16)

        except:
            return None, None

    elif offset.isdigit():
        try:
            offset = int(offset)

        except:
            return None, None

    else:
        return None, None

    if sep == '-':
        offset = offset * -1

    return register, offset


def analyze_for_MemStore(gadget):
    instructions = gadget['instructions']
    address = gadget['address']
    first_instr = x86Instruction(instructions[0])
    mem_addr_reg = None
    mem_addr_offset = 0
    value_reg = None

    def MemStore_finish_analysis():
        emu = x86Emulator(bits=GADGETS_ARCH_BITS)
        stack_ptr = emu.get_stack_pointer_value()
        write_address = stack_ptr - 0x300
        emu.set_register_value(mem_addr_reg, write_address - mem_addr_offset)

        if emu.BITS == 64:
            write_value = 0x3a4a5a6a7a8a9aba
            write_size = 8

        else:
            write_value = 0x3a4a5a6a
            write_size = 4

        emu.set_register_value(value_reg, write_value)

        initial_state = get_emulator_state(emu)
        emu = execute_gadget(emu, instructions)

        data = emu.read_mem(write_address, write_size)
        if write_size == 8:
            data = struct.unpack('<Q', data)[0]

        else:
            data = struct.unpack('<I', data)[0]

        if data == write_value:
            new_state = get_emulator_state(emu)

            mem_taint_exceptions = [write_address + i for i in range(write_size)]
            state_transition_info = get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[], mem_taint_exceptions=mem_taint_exceptions, additional_penalty=abs(mem_addr_offset) * PENALTY_FOR_INSTRUCTION_WITH_OFFSET)
            grade = state_transition_info['grade']
            tainted_regs = state_transition_info['tainted-registers']

            add_to_MemStore(mem_addr_reg, value_reg, Chain([Gadget(address, instructions, state_transition_info)]))


    if first_instr.mnemonic == 'mov' and '[' in first_instr.first_operand and first_instr.second_operand in ALL_KNOWN_REGISTERS:
        i = first_instr.first_operand.find('[')
        j = first_instr.first_operand.find(']')

        if i != -1 and j != -1:
            text = first_instr.first_operand[i+1:j]

            if text in ALL_KNOWN_REGISTERS and text != first_instr.second_operand:
                mem_addr_reg = text
                value_reg = first_instr.second_operand

                MemStore_finish_analysis()

            else:
                register, offset = get_register_and_offset_from_memory_operation(first_instr.first_operand)

                if register != None and offset != None and register in ALL_KNOWN_REGISTERS:
                    mem_addr_reg = register
                    mem_addr_offset = offset
                    value_reg = first_instr.second_operand

                    MemStore_finish_analysis()


    elif first_instr.mnemonic == 'xchg':
        condition1 = '[' in first_instr.first_operand and first_instr.second_operand in ALL_KNOWN_REGISTERS
        condition2 = '[' in first_instr.second_operand and first_instr.first_operand in ALL_KNOWN_REGISTERS

        if condition1 or condition2:
            if condition1:
                value_reg = first_instr.second_operand
                text = first_instr.first_operand

            elif condition2:
                value_reg = first_instr.first_operand
                text = first_instr.second_operand

            i = text.find('[')
            j = text.find(']')

            tmp = text[i+1:j]

            if tmp in ALL_KNOWN_REGISTERS and tmp != value_reg:
                mem_addr_reg = tmp
                MemStore_finish_analysis()

            else:
                register, offset = get_register_and_offset_from_memory_operation(text)

                if register != None and offset != None and register in ALL_KNOWN_REGISTERS:
                    mem_addr_reg = register
                    mem_addr_offset = offset
                    MemStore_finish_analysis()

def add_to_MemRead(mem_addr_reg: str, value_reg: str, chain: Chain):
    global MemRead_chains

    if MemRead_chains.get(mem_addr_reg, None) == None:
        MemRead_chains[mem_addr_reg] = {}

    if MemRead_chains[mem_addr_reg].get(value_reg, None) == None:
        MemRead_chains[mem_addr_reg][value_reg] = []

    MemRead_chains[mem_addr_reg][value_reg].append(chain)


def analyze_for_MemRead(gadget):
    instructions = gadget['instructions']
    address = gadget['address']
    first_instr = x86Instruction(instructions[0])
    mem_addr_reg = None
    value_reg = None
    mem_addr_offset = 0

    def MemRead_finish_analysis():
        emu = x86Emulator(bits=GADGETS_ARCH_BITS)
        stack_ptr = emu.get_stack_pointer_value()
        write_address = stack_ptr - 0x300

        if emu.BITS == 64:
            write_value = 0x3a4a5a6a7a8a9aba
            write_size = 8
            data = struct.pack('<Q', write_value)

        else:
            write_value = 0x3a4a5a6a
            write_size = 4
            data = struct.pack('<I', write_value)

        emu.write_mem(write_address, data)
        emu.set_register_value(mem_addr_reg, write_address - mem_addr_offset)

        initial_state = get_emulator_state(emu)
        emu = execute_gadget(emu, instructions)

        data = emu.get_register_value(value_reg)

        if data == write_value:
            new_state = get_emulator_state(emu)

            state_transition_info = get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[value_reg], additional_penalty=abs(mem_addr_offset) * PENALTY_FOR_INSTRUCTION_WITH_OFFSET)
            grade = state_transition_info['grade']
            tainted_regs = state_transition_info['tainted-registers']

            add_to_MemRead(mem_addr_reg, value_reg, Chain([Gadget(address, instructions, state_transition_info)]))


    if first_instr.mnemonic == 'mov' and first_instr.first_operand in ALL_KNOWN_REGISTERS and '[' in first_instr.second_operand:
        i = first_instr.second_operand.find('[')
        j = first_instr.second_operand.find(']')

        if i != -1 and j != -1:
            text = first_instr.second_operand[i+1:j]

            if text in ALL_KNOWN_REGISTERS:
                mem_addr_reg = text
                value_reg = first_instr.first_operand

                MemRead_finish_analysis()

            else:
                register, offset = get_register_and_offset_from_memory_operation(first_instr.second_operand)

                if register != None and offset != None and register in ALL_KNOWN_REGISTERS:
                    value_reg = first_instr.first_operand
                    mem_addr_reg = register
                    mem_addr_offset = offset

                    MemRead_finish_analysis()

    elif first_instr.mnemonic == 'xchg':
        condition1 = '[' in first_instr.first_operand and first_instr.second_operand in ALL_KNOWN_REGISTERS
        condition2 = '[' in first_instr.second_operand and first_instr.first_operand in ALL_KNOWN_REGISTERS

        if condition1 or condition2:
            if condition1:
                value_reg = first_instr.second_operand
                text = first_instr.first_operand

            elif condition2:
                value_reg = first_instr.first_operand
                text = first_instr.second_operand

            i = text.find('[')
            j = text.find(']')

            tmp = text[i+1:j]

            if tmp in ALL_KNOWN_REGISTERS:
                mem_addr_reg = tmp
                MemRead_finish_analysis()

            else:
                register, offset = get_register_and_offset_from_memory_operation(text)

                if register != None and offset != None and register in ALL_KNOWN_REGISTERS:
                    mem_addr_reg = register
                    mem_addr_offset = offset

                    MemRead_finish_analysis()


def notify_exception(e):
    if 'Unknown instruction' in str(e):
        pass

    elif 'Unknown operand' in str(e):
        pass

    elif 'Unsafe eval' in str(e):
        pass

    elif 'Invalid operand' in str(e):
        pass

    else:
        print(e)
        traceback.print_exc()


def sort_semantic_gadgets(quiet=False):
    if quiet == False:
        log_info('[+] Sorting semantic gadgets by quality...')

    single_nested_key_lists = [ZeroReg_chains, LoadConst_chains]
    double_nested_key_lists = [MoveReg_chains, AddReg_chains, SubReg_chains, MemStore_chains, MemRead_chains]

    for item in single_nested_key_lists:
        for key in item.keys():
            sorted_list = sorted(item[key], key=lambda x: x.grade)
            item[key] = sorted_list

    for item in double_nested_key_lists:
        for key1 in item.keys():
            for key2 in item.get(key1, {}).keys():
                sorted_list = sorted(item[key1][key2], key=lambda x: x.grade)
                item[key1][key2] = sorted_list

def join_chains(chain_list):
    gadgets = []

    for chain in chain_list:
        for gadget in chain.gadgets:
            gadgets.append(gadget)

    return Chain(gadgets)


def expand_chain_to_instructions(chain):
    instructions = []

    for gadget in chain.gadgets:
        instructions += gadget.instructions

    return instructions


def populate_LoadConstAuxiliary():
    log_info('[+] Building auxiliary gadgets for LoadConst...')
    # LoadConstAuxiliary_chains = {'register-to-modify': {'type': [Chain, Chain, Chain...]}}
    # AddReg_chains = {'register-store': {'register-adder': [Chain, Chain, Chain...]}}
    auxiliary_types = ['just-load', 'neg-after-load', 'not-after-load', 'add-after-load', 'sub-after-load']

    good_loadconst_chains = {}
    for load_const_reg in LoadConst_chains.keys():
        count = 0
        for load_const_chain in LoadConst_chains[load_const_reg]:
            if load_const_chain.grade >= PENALTY_PER_EXCEPTION or count >= 5:
                break

            if good_loadconst_chains.get(load_const_reg, None) == None:
                good_loadconst_chains[load_const_reg] = []

            good_loadconst_chains[load_const_reg].append(load_const_chain)
            count += 1

    for load_const_reg in good_loadconst_chains.keys():
        for load_const_chain in good_loadconst_chains[load_const_reg]:
            for auxiliary_type in auxiliary_types:
                if auxiliary_type == 'just-load':
                    item = []
                    copy_load_const_chain = copy.deepcopy(load_const_chain)
                    copy_load_const_chain.gadgets[0].intentional_stack_movement_before_ret = True
                    item.append(copy_load_const_chain)

                    item.append(Chain([Gadget('0xaaaaaaaa', [], {}, comments='CONSTANT1', gadget_type='constant')]))

                    add_to_LoadConstAuxiliary(load_const_reg, auxiliary_type, join_chains(item))

                elif auxiliary_type == 'neg-after-load':
                    # Get only the first 5 NegReg chains
                    for neg_chain in NegReg_chains.get(load_const_reg, [])[:5]:
                        if neg_chain.grade >= PENALTY_PER_EXCEPTION:
                            continue

                        item = []
                        copy_load_const_chain = copy.deepcopy(load_const_chain)
                        copy_load_const_chain.gadgets[0].intentional_stack_movement_before_ret = True
                        item.append(copy_load_const_chain)
                        item.append(Chain([Gadget('0xaaaaaaaa', [], {}, comments='CONSTANT1', gadget_type='constant')]))
                        item.append(neg_chain)

                        add_to_LoadConstAuxiliary(load_const_reg, auxiliary_type, join_chains(item))

                elif auxiliary_type == 'not-after-load':
                    # Get only the first 5 NotReg chains
                    for not_chain in NotReg_chains.get(load_const_reg, [])[:5]:
                        if not_chain.grade >= PENALTY_PER_EXCEPTION:
                            continue

                        item = []
                        copy_load_const_chain = copy.deepcopy(load_const_chain)
                        copy_load_const_chain.gadgets[0].intentional_stack_movement_before_ret = True
                        item.append(copy_load_const_chain)
                        item.append(Chain([Gadget('0xaaaaaaaa', [], {}, comments='CONSTANT1', gadget_type='constant')]))
                        item.append(not_chain)

                        add_to_LoadConstAuxiliary(load_const_reg, auxiliary_type, join_chains(item))

                elif auxiliary_type == 'add-after-load':
                    for adder_reg in AddReg_chains.get(load_const_reg, {}).keys():
                        for load_const_chain_2 in good_loadconst_chains.get(adder_reg, []):
                            # Get only the first AddReg chain
                            add_chain = AddReg_chains[load_const_reg][adder_reg][0]
                            if add_chain.grade >= PENALTY_PER_EXCEPTION:
                                continue

                            if load_const_reg in load_const_chain_2.tainted_regs:
                                continue

                            if load_const_reg in add_chain.tainted_regs:
                                continue

                            item = []
                            copy_load_const_chain = copy.deepcopy(load_const_chain)
                            copy_load_const_chain.gadgets[0].intentional_stack_movement_before_ret = True
                            item.append(copy_load_const_chain)

                            # Gadget(address, instructions, state_transition_info, comments)
                            item.append(Chain([Gadget('0xaaaaaaaa', [], {}, comments='CONSTANT1', gadget_type='constant')]))

                            copy_load_const_chain_2 = copy.deepcopy(load_const_chain_2)
                            copy_load_const_chain_2.gadgets[0].intentional_stack_movement_before_ret = True

                            item.append(copy_load_const_chain_2)

                            # Gadget(address, instructions, state_transition_info, comments)
                            item.append(Chain([Gadget('0xbbbbbbbb', [], {}, comments='CONSTANT2', gadget_type='constant')]))

                            
                            item.append(add_chain)

                            add_to_LoadConstAuxiliary(load_const_reg, auxiliary_type, join_chains(item))

                elif auxiliary_type == 'sub-after-load':
                    for subber_reg in SubReg_chains.get(load_const_reg, {}).keys():
                        for load_const_chain_2 in good_loadconst_chains.get(subber_reg, []):
                            # Get only the first SubReg chain
                            sub_chain = SubReg_chains[load_const_reg][subber_reg][0]
                            if sub_chain.grade >= PENALTY_PER_EXCEPTION:
                                continue

                            if load_const_reg in load_const_chain_2.tainted_regs:
                                continue

                            if load_const_reg in sub_chain.tainted_regs:
                                continue

                            item = []
                            copy_load_const_chain = copy.deepcopy(load_const_chain)
                            copy_load_const_chain.gadgets[0].intentional_stack_movement_before_ret = True
                            item.append(copy_load_const_chain)

                            # Gadget(address, instructions, state_transition_info, comments)
                            item.append(Chain([Gadget('0xaaaaaaaa', [], {}, comments='CONSTANT1', gadget_type='constant')]))

                            copy_load_const_chain_2 = copy.deepcopy(load_const_chain_2)
                            copy_load_const_chain_2.gadgets[0].intentional_stack_movement_before_ret = True
                            item.append(copy_load_const_chain_2)

                            # Gadget(address, instructions, state_transition_info, comments)
                            item.append(Chain([Gadget('0xbbbbbbbb', [], {}, comments='CONSTANT2', gadget_type='constant')]))

                            
                            item.append(sub_chain)

                            add_to_LoadConstAuxiliary(load_const_reg, auxiliary_type, join_chains(item))

    for key1 in LoadConstAuxiliary_chains.keys():
        for key2 in LoadConstAuxiliary_chains[key1].keys():
            sorted_list = sorted(LoadConstAuxiliary_chains[key1][key2], key=lambda x: x.grade)
            LoadConstAuxiliary_chains[key1][key2] = sorted_list


# Use graph theory to find more moves
# Example: if we have a chain for eax -> ebx and a chain for ebx -> ecx, so we have a chain for eax -> ecx
def discover_more_moves():
    new_chains_count = 0

    sys.stdout.write('\r[+] Discovering new MoveReg chains... {0}'.format(new_chains_count))
    sys.stdout.flush()

    if GADGETS_ARCH_BITS == 64:
        registers = KNOWN_REGISTERS_64

    else:
        registers = KNOWN_REGISTERS_32

    for _ in range(10):
        flag_new_gadgets_added = False

        graph = Graph(vertex_count=len(registers))
        best_chains = {}

        def add_best_chain(src, dst, chain):
            if best_chains.get(src, None) == None:
                best_chains[src] = {}

            best_chains[src][dst] = chain

        def derive_shortest_path_in_tuples(shortest_path):
            length = len(shortest_path)
            if length == 0:
                return []

            elif length == 1:
                return [(shortest_path[0], shortest_path[0])]

            i = 1
            tuple_list = []
            while i < length:
                tuple_list.append((shortest_path[i-1], shortest_path[i]))
                i += 1

            return tuple_list

        for i, src_reg in enumerate(registers):
            for j, dst_reg in enumerate(registers):
                if src_reg == dst_reg:
                    continue

                # MoveReg_chains = {'register-src': {'register-dst': [Chain, Chain, Chain...]}}
                chains = MoveReg_chains.get(src_reg, {}).get(dst_reg, [])

                if len(chains) == 0:
                    continue

                best_chain = chains[0]

                if 'esp' in best_chain.tainted_regs or 'rsp' in best_chain.tainted_regs:
                    # Don't try to chain gadgets that taints stack pointer
                    continue

                graph.set_distance(i, j, best_chain.grade)
                add_best_chain(src_reg, dst_reg, best_chain)

        graph.calculate_shortest_path()

        for i, src_reg in enumerate(registers):
            for j, dst_reg in enumerate(registers):
                if src_reg == dst_reg:
                    continue

                shortest_path = graph.get_shortest_path(i, j)
                shortest_path_names = list(map(lambda x: registers[x], shortest_path))

                if len(shortest_path) > 2:
                    tuple_list = derive_shortest_path_in_tuples(shortest_path_names)

                    new_chain_list = []
                    for t in tuple_list:
                        new_chain_list.append(best_chains[t[0]][t[1]])

                    new_chain = join_chains(new_chain_list)

                    instructions = expand_chain_to_instructions(new_chain)

                    def discover_more_moves_finish_analysis():
                        nonlocal instructions, new_chains_count
                        emu = x86Emulator(bits=GADGETS_ARCH_BITS)
                        expected_value = emu.get_register_value(src_reg)
                        initial_state = get_emulator_state(emu)
                        emu = execute_gadget(emu, instructions)
                        
                        if emu.get_register_value(dst_reg) == expected_value:
                            new_state = get_emulator_state(emu)
                            state_transition_info = get_state_transition_info(instructions, initial_state, new_state, taint_exceptions=[dst_reg])
                            grade = state_transition_info['grade']
                            tainted_regs = state_transition_info['tainted-registers']

                            add_to_MoveReg(src_reg, dst_reg, new_chain)

                            new_chains_count += 1
                            flag_new_gadgets_added = True

                            sys.stdout.write('\r[+] Discovering new MoveReg chains... {0}'.format(new_chains_count))
                            sys.stdout.flush()

                    discover_more_moves_finish_analysis()
                    
        sort_semantic_gadgets(quiet=True)
        if flag_new_gadgets_added == False:
            break

    sys.stdout.write('\n')
    sys.stdout.flush()


def populate_StackPivot():
    global StackPivot_chains
    global AddStackPtrConst_chains
    global SubStackPtrConst_chains
    global MoveReg_chains, AddReg_chains, SubReg_chains

    log_info('[+] Building gadgets for StackPivot...')

    if GADGETS_ARCH_BITS == 64:
        stack_ptr = 'rsp'
        base_ptr = 'rbp'

    else:
        stack_ptr = 'esp'
        base_ptr = 'ebp'

    for reg in ALL_KNOWN_REGISTERS:
        if reg in ['esp', 'rsp']:
            continue

        chains =  MoveReg_chains.get(reg, {}).get(stack_ptr, [])
        chains += AddReg_chains.get(stack_ptr, {}).get(reg, [])
        chains += SubReg_chains.get(stack_ptr, {}).get(reg, [])

        if chains:
            if StackPivot_chains.get(reg, None) == None:
                StackPivot_chains[reg] = []

            StackPivot_chains[reg] += copy.deepcopy(chains)

    for constant in AddStackPtrConst_chains.keys():
        chains = AddStackPtrConst_chains[constant]

        if StackPivot_chains.get(constant, None) == None:
            StackPivot_chains[constant] = []

        StackPivot_chains[constant] += copy.deepcopy(chains)

    for constant in SubStackPtrConst_chains.keys():
        chains = SubStackPtrConst_chains[constant]

        if StackPivot_chains.get(constant, None) == None:
            StackPivot_chains[constant] = []

        StackPivot_chains[constant] += copy.deepcopy(chains)


    for key in StackPivot_chains.keys():
        StackPivot_chains[key] = sorted(StackPivot_chains[key], key=lambda x: x.grade)


def populate_GetStackPtr():
    global GetStackPtr_chains

    log_info('[+] Building gadgets for GetStackPtr...')

    if GADGETS_ARCH_BITS == 64:
        stack_ptr = 'rsp'
        base_ptr = 'rbp'

    else:
        stack_ptr = 'esp'
        base_ptr = 'ebp'

    for reg in ALL_KNOWN_REGISTERS:
        if reg in ['esp', 'rsp']:
            continue

        chains =  MoveReg_chains.get(stack_ptr, {}).get(reg, [])
        chains += AddReg_chains.get(reg, {}).get(stack_ptr, [])
        chains += SubReg_chains.get(reg, {}).get(stack_ptr, [])

        if chains:
            if GetStackPtr_chains.get(reg, None) == None:
                GetStackPtr_chains[reg] = []

            GetStackPtr_chains[reg] += copy.deepcopy(chains)

        chains =  copy.deepcopy(MoveReg_chains.get(base_ptr, {}).get(reg, []))
        chains += copy.deepcopy(AddReg_chains.get(reg, {}).get(base_ptr, []))
        chains += copy.deepcopy(SubReg_chains.get(reg, {}).get(base_ptr, []))

        for chain in chains:
            chain.grade += PENALTY_GET_STACK_PTR_WITH_EBP

        if chains:
            if GetStackPtr_chains.get(reg, None) == None:
                GetStackPtr_chains[reg] = []

            GetStackPtr_chains[reg] += copy.deepcopy(chains)

    for reg in GetStackPtr_chains.keys():
        GetStackPtr_chains[reg] = sorted(GetStackPtr_chains[reg], key=lambda x: x.grade)


def initialize_semantic_gadgets(gadgets):
    analyzers = []
    analyzers.append(analyze_for_ZeroReg)
    analyzers.append(analyze_for_MovReg)
    analyzers.append(analyze_for_LoadConst)
    analyzers.append(analyze_for_AddReg)
    analyzers.append(analyze_for_SubReg)
    analyzers.append(analyze_for_MemStore)
    analyzers.append(analyze_for_MemRead)
    analyzers.append(analyze_for_NegReg)
    analyzers.append(analyze_for_NotReg)
    analyzers.append(analyze_for_AddStackPtrConst)
    analyzers.append(analyze_for_SubStackPtrConst)

    num_gadgets = len(gadgets)

    slowest_time = 0
    slowest_gadget = None
    for i, gadget in enumerate(gadgets):
        sys.stdout.write('\r[+] Analyzing gadgets... {0:03}%'.format(int(((i+1) / num_gadgets) * 100)))
        sys.stdout.flush()

        try:
            for analyzer in analyzers:
                analyzer(gadget)

        except Exception as e:
            notify_exception(e)

    sys.stdout.write('\r\n')
    sys.stdout.flush()

    # add_to_ZeroReg('eax', Chain([Gadget('0xfafafafa', ['mov eax, 0x1', 'ret'], 1, []), Gadget('0xfafafafb', ['inc eax', 'ret'], 1, []), Gadget('0xfafafafc', ['dec eax', 'ret'], 1, []), Gadget('0xfafafafc', ['dec eax', 'ret'], 1, [])]))
    sort_semantic_gadgets()

    discover_more_moves()

    # call this only after sorting semantic gadgets
    populate_LoadConstAuxiliary()
    populate_GetStackPtr()
    populate_StackPivot()

def input_swallowing_interrupt(_input):
    def _input_swallowing_interrupt(*args):
        try:
            return _input(*args)

        except KeyboardInterrupt:
            print('^C')
            return '\n'

        except EOFError:
            print('exit')
            return 'exit\n'

    return _input_swallowing_interrupt


class Graph:
    INFINITE_DISTANCE = 2 ** 100

    def __init__(self, vertex_count: int):
        self.graph = []
        self.shortest_distance = []
        self.next = []
        self.__calculated_shortest_path = False

        self.vertex_count = vertex_count

        for i in range(self.vertex_count):
            self.graph.append([Graph.INFINITE_DISTANCE] * self.vertex_count)

    def get_distance(self, src: int, dst: int):
        if src >= self.vertex_count or dst >= self.vertex_count:
            raise Exception('Invalid vertex number')

        return self.graph[src][dst]

    def set_distance(self, src: int, dst: int, distance: int):
        if src >= self.vertex_count or dst >= self.vertex_count:
            raise Exception('Invalid vertex number')

        self.graph[src][dst] = distance

    def get_shortest_distance(self, src: int, dst: int):
        if self.__calculated_shortest_path == False:
            raise Exception('Shortest path not calculated')

        if src >= self.vertex_count or dst >= self.vertex_count:
            raise Exception('Invalid vertex number')

        return self.shortest_distance[src][dst]

    def get_shortest_path(self, src: int, dst:int):
        if self.__calculated_shortest_path == False:
            raise Exception('Shortest path not calculated')

        if self.next[src][dst] == -1:
            return []

        path = [src]

        if src == dst:
            if self.next[src][dst] != dst:
                src = self.next[src][dst]
                path.append(src)

        while src != dst:
            src = self.next[src][dst]
            path.append(src)

        return path

    def calculate_shortest_path(self):
        self.shortest_distance = copy.deepcopy(self.graph)
        self.next = copy.deepcopy(self.shortest_distance)

        for i in range(self.vertex_count):
            for j in range(self.vertex_count):
                if self.shortest_distance[i][j] == Graph.INFINITE_DISTANCE:
                    self.next[i][j] = -1

                else:
                    self.next[i][j] = j

        # Floyd Warshall
        for k in range(self.vertex_count):
            for i in range(self.vertex_count):
                for j in range(self.vertex_count):
                    if self.shortest_distance[i][k] == Graph.INFINITE_DISTANCE or self.shortest_distance[k][j] == Graph.INFINITE_DISTANCE:
                        continue

                    if self.shortest_distance[i][k] + self.shortest_distance[k][j] < self.shortest_distance[i][j]:
                        self.shortest_distance[i][j] = self.shortest_distance[i][k] + self.shortest_distance[k][j]
                        self.next[i][j] = self.next[i][k]

        self.__calculated_shortest_path = True


class RopShell(cmd.Cmd):
    def __init__(self, color=True):
        setattr(RopShell, 'do_append-chain', RopShell.appendchain)
        setattr(RopShell, 'help_append-chain', RopShell.appendchain_help)

        self.__color_enabled = color

        self.identchars += '-'
        cmd.Cmd.__init__(self)

        if self.__color_enabled:
            self.prompt = '\033[1;31m' + 'smartchainer> ' + '\033[0m'

        else:
            self.prompt = 'smartchainer> '

        self.list_in_context = None
        self.list_name_in_context = None
        self.register_to_preserve_in_context = None

        self.rop_chain = []
        self.rop_chain_registers_to_preserve = []
        self.rop_chain_variable_name = 'rop_chain'
        self.config_dummy_value()

        self.calculate_stats_semantic_gadgets()

        self.config_enable_auto_preserving_regs = False

    def config_dummy_value(self):
        global BAD_CHARS

        possible_b = bytearray(b'\xaa\xbb\xdd\xee\x11\x22\x33\x44\x55\x66\x77\x88\x99')

        for i in range(1, 0xff):
            if i not in possible_b:
                if i not in b'\xcc\x90\x00\x0a\x0d':
                    possible_b += bytearray(i)

        chosen_one = None
        for b in possible_b:
            if b not in BAD_CHARS:
                chosen_one = b
                break

        if chosen_one == None:
            raise Exception('Unable to find an available dummy value')

        if GADGETS_ARCH_BITS == 64:
            self.DUMMY_VALUE_FOR_ROP = struct.unpack('<Q', chosen_one.to_bytes(1, 'big') * 8)[0]

        else:
            self.DUMMY_VALUE_FOR_ROP = struct.unpack('<I', chosen_one.to_bytes(1, 'big') * 4)[0]

    def color_good(self, msg):
        if self.__color_enabled:
            return '\033[0;34m{0}\033[0m'.format(msg)

        return msg

    def color_medium(self, msg):
        if self.__color_enabled:
            return '\033[33m{0}\033[0m'.format(msg)

        return msg


    def color_bad(self, msg):
        if self.__color_enabled:
            return '\033[31m{0}\033[0m'.format(msg)

        return msg

    def color_grade(self, grade):
        if grade < PENALTY_PER_MEMORY_DIFF:
            return self.color_good('{0}'.format(grade))

        elif grade < PENALTY_PER_STACK_MOVEMENT_NEGATIVE:
            return self.color_medium('{0}'.format(grade))

        else:
            return self.color_bad('{0}'.format(grade))


    def calculate_stats_semantic_gadgets(self):
        single_nested_key_lists = [('ZeroReg', ZeroReg_chains), ('GetStackPtr', GetStackPtr_chains)]

        double_nested_key_lists = [('MoveReg', MoveReg_chains), ('AddReg', AddReg_chains)]
        double_nested_key_lists += [('SubReg', SubReg_chains), ('StoreMem', MemStore_chains), ('ReadMem', MemRead_chains)]

        special_list_LoadConstAuxiliary = ('LoadConstAvoidBadChar', LoadConstAuxiliary_chains)
        load_const_list = ('LoadConst', LoadConstAuxiliary_chains)

        special_list_StackPivot = ('StackPivot', StackPivot_chains)
        
        def calculate_stats_rank_for_list(chain_list):
            if len(chain_list) == 0:
                return PENALTY_REALLY_HIGH

            return chain_list[0].grade

        stats = {}

        for name, item in single_nested_key_lists:
            stats[name] = []
            for key in item.keys():
                grade = calculate_stats_rank_for_list(item[key])
                stats[name].append((key, grade))

            stats[name] = sorted(stats[name], key=lambda x: x[1])

        for name, item in double_nested_key_lists:
            stats[name] = []
            for key1 in item.keys():
                for key2 in item.get(key1, {}).keys():
                    if key2 in ALL_KNOWN_REGISTERS:
                        grade = calculate_stats_rank_for_list(item[key1][key2])
                        stats[name].append((key1, key2, grade))

            stats[name] = sorted(stats[name], key=lambda x: x[2])

            if name in ['AddReg', 'SubReg']:
                if len(stats[name]) > 0:
                    biggest_grade = stats[name][-1][2]
                    for key in item.keys():                    
                        stats[name].append((key, '<constant>', biggest_grade + 1))

        name, item = special_list_LoadConstAuxiliary
        stats[name] = []
        for reg in item.keys():
            lowest_grade = PENALTY_REALLY_HIGH
            for auxiliary_type in item[reg].keys():
                if auxiliary_type != 'just-load':
                    grade = calculate_stats_rank_for_list(item[reg][auxiliary_type])
                    if grade < lowest_grade:
                        lowest_grade = grade

            stats[name].append((reg, lowest_grade))

        stats[name] = sorted(stats[name], key=lambda x: x[1])

        name, item = load_const_list
        stats[name] = []
        for reg in item.keys():
            grade = calculate_stats_rank_for_list(item[reg].get('just-load', []))
            stats[name].append((reg, grade))

        stats[name] = sorted(stats[name], key=lambda x: x[1])


        name, item = special_list_StackPivot
        stats[name] = []
        for key in item.keys():
            if key in ALL_KNOWN_REGISTERS:
                grade = calculate_stats_rank_for_list(item[key])
                stats[name].append((key, grade))

        stats[name] = sorted(stats[name], key=lambda x: x[1])

        if len(stats[name]) > 0:
            biggest_grade = stats[name][-1][1]
            stats[name].append(('<constant>', biggest_grade + 1))

        self.stats = stats

    def completenames(self, text, *ignored):
        dotext = 'do_' + text
        #return [a[3:]+' ' for a in self.get_names() if a.startswith(dotext)]
        return [a[3:]+' ' for a in self.get_names() if a.lower().startswith(dotext.lower())]  # case insensitive

    def do_show(self, in_args):
        if in_args == 'rop-chain':
            self.showropchain(in_args)

        elif in_args == 'preserved-regs':
            if self.rop_chain_registers_to_preserve == []:
                print('\nNo registers are being preserved\n')

            else:
                self.show_preserving_regs_if_any()

        else:
            print('\nUnknown command\n')


    def help_show(self):
        print('\n"show rop-chain" command\n')
        print('\tUsage:       show rop-chain\n')
        print('\tDescription: Shows the current ROP Chain being built\n')

        print('\n"show preserved-regs" command\n')
        print('\tUsage:       show preserved-regs\n')
        print('\tDescription: When a given operation (like ZeroReg, MoveReg, AddReg, etc) is appended \n'\
              '\t             to your ROP Chain, the register targeted by the operation is added to a list of \n'\
              "\t             registers to be preserved in subsequent shown operations (you don't want a subsequent \n"\
              '\t             operation messing up with the register you just set). In other words, if you \n'\
              '\t             append a "ZeroReg eax" operation to your ROP Chain, the other \n'\
              '\t             Use this command to show the list of registers being preserved.\n')

    def complete_show(self, text, line, begidx, endidx):
        completions = ['preserved-regs', 'rop-chain']
        
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] + ' ' for s in completions if s.startswith(mline)]

    def complete_help(self, text, line, begidx, endidx):
        completions = [a[5:] for a in self.get_names() if a.startswith('help_')]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        # return [s[offs:] + ' ' for s in completions if s.startswith(mline)]
        return [s[offs:] + ' ' for s in completions if s.lower().startswith(mline.lower())]


    def do_delete(self, in_args):
        items = in_args.split(' ')

        if len(items) < 1:
            print('\nUnknown command\n')
            return

        if items[0] == 'preserved-reg':
            if len(items) != 2:
                print('\nInvalid parameters. You must specify which register to delete from\n'\
                     'the preserving list or specify "all" to delete all registers.\n')

                return

            self.flush_registers_to_preserve(items[1])

        elif items[0] == 'rop-chain':
            if len(items) != 2:
                print('\nInvalid parameters. You must specify "last-item" to delete the last\n'\
                      'item in the rop chain or "all" to delete the complete rop chain.\n')
                return

            self.delete_from_ropchain(items[1])

        else:
            print('\nUnknown command\n')

    def help_delete(self):
        print('\n"delete rop-chain" command')
        print('\tUsage:       delete rop-chain')
        print('\tDescription: Resets the ROP Chain you were building with the "append-chain" command\n')

        print('\n"delete preserved-reg" command\n')
        print('\tUsage:       delete preserved-reg <register-to-stop-preserving | all>\n')
        print('\tExamples:    delete preserved-reg eax')
        print('\t             delete preserved-reg ebx')
        print('\t             delete preserved-reg all\n')
        print('\tDescription: When a given operation (like ZeroReg, MoveReg, AddReg, etc) is appended \n'\
              '\t             to your ROP Chain, the register targeted by the operation is added to a list of \n'\
              "\t             registers to be preserved in subsequent shown operations (you don't want a subsequent \n"\
              '\t             operation messing up with the register you just set). In other words, if you \n'\
              '\t             append a "ZeroReg eax" operation to your ROP Chain, the other \n'\
              '\t             Use this command to clear the list of registers being preserved.\n')

    def complete_delete(self, text, line, begidx, endidx):
        completions = ['preserved-reg', 'rop-chain all', 'rop-chain last-item']

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] + ' ' for s in completions if s.startswith(mline)]


    def do_add(self, in_args):
        items = in_args.split(' ')

        if len(items) < 1:
            print('\nInvalid argument\n')
            return

        if items[0] == 'preserved-reg':
            if len(items) != 2:
                print('\nYou must specify the register to be added\n')
                return

            if items[1] not in ALL_KNOWN_REGISTERS:
                print('\nUnknown register name: {0}'.format(items[1]))
                return

            if items[1] in self.rop_chain_registers_to_preserve:
                print('\nRegister {0} is already being preserved\n'.format(items[1]))
                return

            self.rop_chain_registers_to_preserve.append(items[1])
            print('\nDone\n')
            return

        print('\nInvalid argument\n')

    def complete_add(self, text, line, begidx, endidx):
        completions = ['preserved-reg']

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] + ' ' for s in completions if s.startswith(mline)]

    def help_add(self):
        print('\n"add preserved-reg" command')
        print('\tUsage:       add preserved-reg <register-name>')
        print('\tExample:     add preserved-reg eax\n')
        print('\tDescription: When you use an operation like MoveReg or ZeroReg, the listing chains will exclude\n'\
              '\t             from the listing those chains that taints the registers being preserved.\n'\
              '\t             Use this command to add a register to the list of registers being preserved.\n')


    def cmdloop(self, *args, **kwargs):
        old_input_fn = cmd.__builtins__['input']
        cmd.__builtins__['input'] = input_swallowing_interrupt(old_input_fn)
        try:
            super().cmdloop(*args, **kwargs)
        finally:
            cmd.__builtins__['input'] = old_input_fn

    def do_exit(self, in_args):
        ans = input('Are you sure you want to exit? [y/N]: ')
        if ans.lower() == 'y':
            raise SystemExit

    def help_exit(self):
        print('\nexit command:')
        print('\tCleans up and quit\n')

    def delete_from_ropchain(self, in_args):
        if in_args == 'all':
            if self.rop_chain == []:
                print('\nROP Chain is already empty\n')
                return

            self.showropchain(None)
            ans = input('Are you sure you want to reset this ROP Chain? [y/N]: ')

            if ans.lower() == 'y':
                self.rop_chain = []
                self.rop_chain_registers_to_preserve = []
                print('\nDone!\n')

        elif in_args == 'last-item':
            if self.rop_chain == []:
                print('\nROP Chain is empty\n')
                return

            self.showropchain(None, highlight_item=len(self.rop_chain)-1)
            ans = input('Are you sure you want to delete the highlighted item from the ROP Chain? [y/N]: ')

            if ans.lower() == 'y':
                self.rop_chain = self.rop_chain[:-1]
                print('\nDone!\n')

        else:
            print('\nInvalid parameter.\n')
            return

    def flush_registers_to_preserve(self, in_args):
        if in_args == 'all':
            self.rop_chain_registers_to_preserve = []
            print('\nDone!\n')
            return

        elif in_args in ALL_KNOWN_REGISTERS:
            if in_args in self.rop_chain_registers_to_preserve:
                self.rop_chain_registers_to_preserve.remove(in_args)
                print('\nDone!\n')
                return

            else:
                print('\nRegister {0} is not being preserved.\n'.format(in_args))
                return

        print('\nInvalid arg: {0}'.format(in_args))

    def show_preserving_regs_if_any(self):
        if self.rop_chain_registers_to_preserve:
            print('\nPreserving registers: [{0}]\n'.format(self.color_good(', '.join(self.rop_chain_registers_to_preserve))))

    def serve_chain_list(self, chain_list, list_name, register_to_preserve, max_to_show):
        self.show_preserving_regs_if_any()
        removed_because_preserve = 0

        new_list = []
        for c in chain_list:
            should_add = True
            for reg in self.rop_chain_registers_to_preserve:
                if reg in c.tainted_regs:
                    should_add = False
                    removed_because_preserve += 1
                    break

            if should_add:
                new_list.append(c)

        self.list_in_context = new_list
        self.list_name_in_context = list_name
        self.register_to_preserve_in_context = register_to_preserve

        if removed_because_preserve > 0:
            print('{0} chains ommited for tainting preserved registers\n'.format(self.color_bad(str(removed_because_preserve))))

        if len(self.list_in_context) == 0:
            print('\nNo chains found for "{0}"\n'.format(self.list_name_in_context))
            return

        print('\nChains for {0}'.format(self.list_name_in_context))

        if len(self.rop_chain_registers_to_preserve) > 0:
            print('** Preserving {0} **'.format(', '.join(self.rop_chain_registers_to_preserve)))

        max_to_show = min(max_to_show, len(self.list_in_context))
        print('(showing {0}, available={1})\n'.format(max_to_show, len(self.list_in_context)))

        rjustify_size = len(str(max_to_show-1))
        for i, chain in enumerate(self.list_in_context):
            if i >= max_to_show:
                break

            chain_number = '{0}'.format(i).rjust(rjustify_size)
            text = '    {0} => '.format(chain_number)
            prepend_size = len(text)
            sys.stdout.write(text + 'Chain rank={0}, taints=[{1}]\n'.format(chain.grade, ', '.join(chain.tainted_regs)))

            for gadget in chain.gadgets:
                prepend = ' ' * prepend_size
                sys.stdout.write(prepend + '{0}\n'.format(gadget))

            sys.stdout.write('\n')

    def effective_append_chain(self, chain_number):
        details = {
            'origin': self.list_name_in_context,
            'chain-number': chain_number,
            'chain': self.list_in_context[chain_number]
        }

        self.rop_chain.append(details)

        if self.register_to_preserve_in_context != None:
            if self.register_to_preserve_in_context not in self.rop_chain_registers_to_preserve:
                if self.config_enable_auto_preserving_regs:
                    self.rop_chain_registers_to_preserve.append(self.register_to_preserve_in_context)

    def showropchain(self, in_args, highlight_item=None):
        print("\n{0} =  b''".format(self.rop_chain_variable_name))
        pack_size = '<I'
        padding_size = 4

        remaining_padding_because_retn = 0

        if GADGETS_ARCH_BITS == 64:
            pack_size = '<Q'
            padding_size = 8

        for index, details in enumerate(self.rop_chain):
            chain = details['chain']

            # Start highlight
            if index == highlight_item:
                if self.__color_enabled:
                    sys.stdout.write('\033[0;34m')

                else:
                    sys.stdout.write('\n++++++++++')

            print('\n# {0} chain'.format(details['origin']))
            for gadget in chain.gadgets:
                if gadget.gadget_type == 'gadget':
                    print("{0} += struct.pack('{1}', {2})  # {3}".format(self.rop_chain_variable_name, pack_size, gadget.address, ' ; '.join(gadget.instructions)))

                    for i in range(remaining_padding_because_retn // padding_size):
                        print("{0} += struct.pack('{1}', {2})  # {3}".format(self.rop_chain_variable_name, pack_size, self.hex_converter(self.DUMMY_VALUE_FOR_ROP), 'PADDING because of retn'))

                    remaining_padding_because_retn = gadget.stack_movement_after_ret

                else:
                    print("{0} += struct.pack('{1}', {2})  # {3}".format(self.rop_chain_variable_name, pack_size, gadget.address, gadget.comments))

                if gadget.intentional_stack_movement_before_ret == False:
                    stack_movement_before_ret = gadget.stack_movement_before_ret
                    if stack_movement_before_ret > padding_size:
                        for i in range((stack_movement_before_ret - padding_size) // padding_size):
                            print("{0} += struct.pack('{1}', {2})  # {3}".format(self.rop_chain_variable_name, pack_size, self.hex_converter(self.DUMMY_VALUE_FOR_ROP), 'PADDING because of stack movement'))

            # End highlight
            if index == highlight_item:
                if self.__color_enabled:
                    sys.stdout.write('\033[0m')

                else:
                    sys.stdout.write('++++++++++\n')

        sys.stdout.write('\n\n')

    def do_CustomValue(self, in_args):
        in_args = in_args.strip()

        if not in_args:
            print('\nYou must specify the custom value\n')
            return

        if not in_args.startswith('0x'):
            print('\nThe arbitrary value must be in form 0x12345678\n')
            return

        try:
            value_integer = int(in_args, 16)

            if value_integer > 0xFFFFFFFF:
                if GADGETS_ARCH_BITS == 32:
                    print('\nThe target arch is 32 bits. You specified a number grater than 0xFFFFFFFF\n')
                    return


            if self.constant_contains_badchar(value_integer):
                print('\n[WARNING] The custom value {0} contains a BADCHAR!'.format(self.hex_converter(value_integer)))

            comments = input('\nSpecify a comment for this gadget: ')

            chain_list = []
            chain_list.append(Chain([Gadget(self.hex_converter(value_integer), [], {}, comments=comments, gadget_type='constant')]))

            self.serve_chain_list(chain_list, list_name='CustomValue[{0}]'.format(in_args), register_to_preserve=None, max_to_show=1)

        except Exception as e:
            print('\nInvalid argument: {0}\n'.format(in_args))
            return

    def showropchain_help(self):
        print('\n"showropchain" command\n')
        print('\tUsage:       showropchain\n')

        print('\tDescription: Shows the ROP Chain you are building.\n')

    def appendchain(self, in_args):
        if not in_args:
            if self.list_in_context == None:
                print("\nYou haven't listed any chains yet\n")
                return

            print('\nLast listed chain: {0}'.format(self.list_name_in_context))
            print('To append a chain from {0}, run "appendchain <chain-number>"\n'.format(self.list_name_in_context))
            return

        if not in_args.isdigit():
            print('Invalid argument\n')
            return

        chain_number = int(in_args)

        if chain_number < 0 or chain_number >= len(self.list_in_context):
            print('Invalid chain number\n')
            return

        chain = self.list_in_context[chain_number]
        self.effective_append_chain(chain_number)

        print('\nAppended {0}[{1}] to your ROP Chain:\n'.format(self.list_name_in_context, chain_number))

        for gadget in chain.gadgets:
            print('\t{0}'.format(gadget))
        
        sys.stdout.write('\n')

    def appendchain_help(self):
        print('\n"appendchain" command\n')
        print('\tUsage:       append <chain-number>')
        print('\tExample:     ZeroReg eax')
        print('\t             appendchain 3\n')
        print('\tDescription: After listing an available chain, \n'\
              '\t             use the command "appendchain <chain-number>" to \n'\
              '\t             append it to your constructed gadget chain\n')

        print('Last listed chain: {0}\n'.format(self.list_name_in_context))

    def do_ReadMem(self, in_args):
        if not in_args:
            self.dump_best_ReadMem()
            return

        items = in_args.split(' ')

        if len(items) == 1:
            if items[0] not in ALL_KNOWN_REGISTERS:
                print('\nInvalid args\n')
                return
                
            self.dump_best_ReadMem(filter_dst=items[0])
            return

        elif len(items) == 2:
            if items[0] == '*' and items[1] == '*':
                self.dump_best_ReadMem()
                return

            elif items[0] == '*' and items[1] in ALL_KNOWN_REGISTERS:
                self.dump_best_ReadMem(filter_src=items[1])
                return

            elif items[1] == '*' and items[0] in ALL_KNOWN_REGISTERS:
                self.dump_best_ReadMem(filter_dst=items[0])
                return

        elif len(items) > 3 or (len(items) == 3 and '*' in items):
            print('\nInvalid args\n')
            return

        value_reg = items[0]
        mem_addr_reg = items[1]

        # MemRead_chains = {'mem-addr-register': {'value-register': [Chain, Chain, Chain]}}
        chain_list = MemRead_chains.get(mem_addr_reg, {}).get(value_reg, None)

        if not chain_list:
            print('\nNo chains found for "ReadMem {0} {1}"\n'.format(mem_addr_reg, value_reg))
            return

        if len(items) == 3:
            if items[2].lower() == 'all':
                max_to_show = len(chain_list)

            elif items[2].isdigit():
                max_to_show = min(len(chain_list), int(items[2]))

            else:
                print('Invalid param for <max-chains-to-show> : {0}'.format(items[2]))
                return

        else:
            max_to_show = 3

        self.serve_chain_list(chain_list, list_name='ReadMem[{0}][{1}]'.format(value_reg, mem_addr_reg), register_to_preserve=value_reg, max_to_show=max_to_show)

    def complete_ReadMem(self, text, line, begidx, endidx):
        tmp = line.split(' ')
        if len(tmp) == 3:
            line = ' '.join(tmp[0:1] + tmp[2:])

        return self.register_completion(text, line, begidx, endidx)

    def help_ReadMem(self):
        print('\n"ReadMem" command\n')
        print('\tUsage:        ReadMem <value-register> <mem-addr-register> [max-chains-to-show | all]')
        print('\tExamples:     ReadMem eax ebx')
        print('\t              ReadMem eax ebx 10')
        print('\t              ReadMem eax ebx all\n')
        print('\tDescription:  Show gadget chains that read data from the memory address pointer by <mem-addr-register> and \n' \
              '\t              saves it into <value-register>.\n')

    def dump_best_GetStackPtr(self):
        print('\nBest GetStackPtr operations:')
        for info in self.stats['GetStackPtr']:
            # GetStackPtr_chains = {'destination-reg': [Chain, Chain, Chain...]}
            chains = GetStackPtr_chains.get(info[0], None)
            if chains:
                print('\tGetStackPtr {0}: {1} chains, first chain with rank {2}'.format(info[0], len(chains), self.color_grade(chains[0].grade)))
        
        print('')

    def complete_GetStackPtr(self, text, line, begidx, endidx):
        return self.register_completion(text, line, begidx, endidx)

    def help_GetStackPtr(self):
        print('\n"GetStackPtr" command\n')
        print('\tUsage:        GetStackPtr <destination-register> [max-chains-to-show | all]')
        print('\tExamples:     GetStackPtr eax')
        print('\t              GetStackPtr eax 10')
        print('\t              GetStackPtr eax all\n')
        print('\tDescription:  Show gadget chains that, in some way, gets the value of stack pointer or an approximate value (like the base pointer).\n')

    def do_GetStackPtr(self, in_args):
        if not in_args:
            self.dump_best_GetStackPtr()
            return

        items = in_args.split(' ')

        if len(items) > 2:
            print('Invalid args\n')
            return

        register = items[0]
        chain_list = GetStackPtr_chains.get(register, None)

        if not chain_list:
            print('\nNo chains found for "GetStackPtr {0}"\n'.format(register))
            return

        if len(items) == 2:
            if items[1].lower() == 'all':
                max_to_show = len(chain_list)

            elif items[1].isdigit():
                max_to_show = min(len(chain_list), int(items[1]))

            else:
                print('Invalid param for <max-chains-to-show> : {0}'.format(items[1]))
                return

        else:
            max_to_show = 3
        
        self.serve_chain_list(chain_list, list_name='GetStackPtr[{0}]'.format(register), register_to_preserve=register, max_to_show=max_to_show)

    def dump_best_StackPivot(self):
        print('\nBest StackPivot operations:')
        for info in self.stats['StackPivot']:
            chains = StackPivot_chains.get(info[0], None)

            if chains:
                print('\tStackPivot {0}: {1} chains, first chain with rank {2}'.format(info[0], len(chains), self.color_grade(chains[0].grade)))

            else:
                if info[0] == '<constant>':
                    chain_count = 0

                    for item in StackPivot_chains.keys():
                        if item not in ALL_KNOWN_REGISTERS:
                            chain_count += 1

                    print('\tStackPivot {0}: {1} chains'.format(info[0], chain_count))
        
        print('')

    def help_StackPivot(self):
        print('\n"StackPivot" command\n')
        print('\tUsage:        StackPivot <src-register | constant> [max-chains-to-show | all]')
        print('\tExamples:     StackPivot eax')
        print('\t              StackPivot eax 10')
        print('\t              StackPivot eax all')
        print('\t              StackPivot 0x10')
        print('\t              StackPivot 0x20\n')
        print('\tDescription:  Show gadget chains that perform stack pivoting. For this command you can specify a register or a constant\n'\
              '\t              If you specify a register, the shown chains are those that the stack pointer will be replaced by the value in the specified register.\n'\
              '\t              If you specify a constant, the shown chains are those that the stack pointer will be incremented by the constant or by an approximate value.\n')

    def do_StackPivot(self, in_args):
        if not in_args:
            self.dump_best_StackPivot()
            return

        items = in_args.split(' ')

        if len(items) > 2:
            print('\nInvalid args\n')
            return

        key = items[0]

        if key in ALL_KNOWN_REGISTERS:
            chain_list = StackPivot_chains.get(key, None)

        elif key.startswith('0x') or key.isdigit():
            try:
                if key.startswith('0x'):
                    constant = int(key, 16)

                else:
                    constant = int(key)

                available_costants = []
                for k in StackPivot_chains.keys():
                    if k.startswith('0x'):
                        available_costants.append((k, int(k, 16)))

                available_costants = sorted(available_costants, key=lambda x: x[1])
                chains = []
                for i, item in enumerate(available_costants):
                    if item[1] < constant:
                        continue

                    chains += StackPivot_chains.get(item[0], [])

                chain_list = chains[:10]

            except Exception as e:
                print(e)
                print('\nInvalid args\n')
                return

        else:
            print('\nInvalid args\n')
            return

        if not chain_list:
            print('\nNo chains found for "StackPivot {0}"\n'.format(key))
            return

        if len(items) == 2:
            if items[1].lower() == 'all':
                max_to_show = len(chain_list)

            elif items[1].isdigit():
                max_to_show = min(len(chain_list), int(items[1]))

            else:
                print('Invalid param for <max-chains-to-show> : {0}'.format(items[1]))
                return

        else:
            max_to_show = 3
        
        self.serve_chain_list(chain_list, list_name='StackPivot[{0}]'.format(key), register_to_preserve=None, max_to_show=max_to_show)


    def do_StoreMem(self, in_args):
        if not in_args:
            self.dump_best_StoreMem()
            return

        items = in_args.split(' ')

        if len(items) == 1:
            if items[0] not in ALL_KNOWN_REGISTERS:
                print('\nInvalid args\n')
                return
                
            self.dump_best_StoreMem(filter_dst=items[0])
            return

        elif len(items) == 2:
            if items[0] == '*' and items[1] == '*':
                self.dump_best_StoreMem()
                return

            elif items[0] == '*' and items[1] in ALL_KNOWN_REGISTERS:
                self.dump_best_StoreMem(filter_src=items[1])
                return

            elif items[1] == '*' and items[0] in ALL_KNOWN_REGISTERS:
                self.dump_best_StoreMem(filter_dst=items[0])
                return

        elif len(items) > 3 or (len(items) == 3 and '*' in items):
            print('\nInvalid args\n')
            return

        mem_addr_reg = items[0]
        value_reg = items[1]

        # MemStore_chains = {'mem-addr-register': {'value-register': [Chain, Chain, Chain]}}
        chain_list = MemStore_chains.get(mem_addr_reg, {}).get(value_reg, None)

        if not chain_list:
            print('\nNo chains found for "StoreMem {0} {1}"\n'.format(mem_addr_reg, value_reg))
            return

        if len(items) == 3:
            if items[2].lower() == 'all':
                max_to_show = len(chain_list)

            elif items[2].isdigit():
                max_to_show = min(len(chain_list), int(items[2]))

            else:
                print('Invalid param for <max-chains-to-show> : {0}'.format(items[2]))
                return

        else:
            max_to_show = 3

        self.serve_chain_list(chain_list, list_name='StoreMem[{0}][{1}]'.format(mem_addr_reg, value_reg), register_to_preserve=None, max_to_show=max_to_show)

    def complete_StoreMem(self, text, line, begidx, endidx):
        tmp = line.split(' ')
        if len(tmp) == 3:
            line = ' '.join(tmp[0:1] + tmp[2:])

        return self.register_completion(text, line, begidx, endidx)

    def help_StoreMem(self):
        print('\n"StoreMem" command\n')
        print('\tUsage:        StoreMem <mem-addr-register> <value-register> [max-chains-to-show | all]')
        print('\tExamples:     StoreMem eax ebx')
        print('\t              StoreMem eax ebx 10')
        print('\t              StoreMem eax ebx all')
        print('\tDescription:  Show gadget chains that store the value in <value-register> into the memory address \n' \
              '\t              pointed by <mem-addr-register>.\n')

    def do_SubReg(self, in_args):
        if not in_args:
            self.dump_best_SubReg()
            return

        if not in_args:
            self.dump_best_SubReg()
            return

        items = in_args.split(' ')

        if len(items) == 1:
            if items[0] not in ALL_KNOWN_REGISTERS:
                print('\nInvalid args\n')
                return

            self.dump_best_SubReg(filter_dst=items[0])
            return

        elif len(items) == 2:
            if items[0] == '*' and items[1] == '*':
                self.dump_best_SubReg()
                return

            elif items[0] == '*' and items[1] in ALL_KNOWN_REGISTERS + ['<constant>']:
                self.dump_best_SubReg(filter_src=items[1])
                return

            elif items[1] == '*' and items[0] in ALL_KNOWN_REGISTERS:
                self.dump_best_SubReg(filter_dst=items[0])
                return

        elif len(items) > 3 or (len(items) == 3 and '*' in items):
            print('\nInvalid args\n')
            return

        dest_reg = items[0]
        subber_reg = items[1]

        if subber_reg.startswith('0x') or subber_reg.isdigit():
            try:
                if subber_reg.startswith('0x'):
                    subber_reg = hex(int(subber_reg, 16))

                else:
                    subber_reg = hex(int(subber_reg))

            except:
                print('Invalid args\n')
                return

        if subber_reg.startswith('0x'):
            try:
                constant = int(subber_reg, 16)

                available_costants = []
                for k in SubReg_chains.get(dest_reg, {}).keys():
                    if k.startswith('0x'):
                        available_costants.append((k, int(k, 16)))

                available_costants = sorted(available_costants, key=lambda x: x[1])
                chains = []
                for i, item in enumerate(available_costants):
                    if item[1] < constant:
                        continue

                    chains += SubReg_chains.get(dest_reg, {}).get(item[0], [])

                chain_list = chains[:10]

            except Exception as e:
                print(e)
                print('\nInvalid args\n')
                return

        else:
            # SubReg_chains = {'register-store': {'register-subber': [Chain, Chain, Chain...]}}
            chain_list = SubReg_chains.get(dest_reg, {}).get(subber_reg, None)


        if not chain_list:
            print('\nNo chains found for "SubReg {0} {1}"\n'.format(dest_reg, subber_reg))
            return

        if len(items) == 3:
            if items[2].lower() == 'all':
                max_to_show = len(chain_list)

            elif items[2].isdigit():
                max_to_show = min(len(chain_list), int(items[2]))

            else:
                print('Invalid param for <max-chains-to-show> : {0}'.format(items[2]))
                return

        else:
            max_to_show = 3

        self.serve_chain_list(chain_list, list_name='SubReg[{0}][{1}]'.format(dest_reg, subber_reg), register_to_preserve=dest_reg, max_to_show=max_to_show)

    def complete_SubReg(self, text, line, begidx, endidx):
        tmp = line.split(' ')
        if len(tmp) == 3:
            line = ' '.join(tmp[0:1] + tmp[2:])

        return self.register_completion(text, line, begidx, endidx)

    def help_SubReg(self):
        print('\n"SubReg" command\n')
        print('\tUsage:        SubReg <dst-register> <subtractor-register> [max-chains-to-show | all]')
        print('\tExamples:     SubReg eax ebx')
        print('\t              SubReg eax ebx 10')
        print('\t              SubReg eax ebx all\n')
        print('\tDescription:  Show gadget chains that subract the value of <subtractor-register> from <dst-register> and \n' \
              '\t              store the result in <dst-register>.\n')

    def do_AddReg(self, in_args):
        if not in_args:
            self.dump_best_AddReg()
            return

        items = in_args.split(' ')

        if len(items) == 1:
            if items[0] not in ALL_KNOWN_REGISTERS:
                print('\nInvalid args\n')
                return

            self.dump_best_AddReg(filter_dst=items[0])
            return

        elif len(items) == 2:
            if items[0] == '*' and items[1] == '*':
                self.dump_best_AddReg()
                return

            elif items[0] == '*' and items[1] in ALL_KNOWN_REGISTERS + ['<constant>']:
                self.dump_best_AddReg(filter_src=items[1])
                return

            elif items[1] == '*' and items[0] in ALL_KNOWN_REGISTERS:
                self.dump_best_AddReg(filter_dst=items[0])
                return

        elif len(items) > 3 or (len(items) == 3 and '*' in items):
            print('\nInvalid args\n')
            return

        dest_reg = items[0]
        adder_reg = items[1]

        if adder_reg.startswith('0x') or adder_reg.isdigit():
            try:
                if adder_reg.startswith('0x'):
                    adder_reg = hex(int(adder_reg, 16))

                else:
                    adder_reg = hex(int(adder_reg))

            except:
                print('Invalid args\n')
                return

        if adder_reg.startswith('0x'):
            try:
                constant = int(adder_reg, 16)

                available_costants = []
                for k in AddReg_chains.get(dest_reg, {}).keys():
                    if k.startswith('0x'):
                        available_costants.append((k, int(k, 16)))

                available_costants = sorted(available_costants, key=lambda x: x[1])
                chains = []
                for i, item in enumerate(available_costants):
                    if item[1] < constant:
                        continue

                    chains += AddReg_chains.get(dest_reg, {}).get(item[0], [])

                chain_list = chains[:10]

            except Exception as e:
                print(e)
                print('\nInvalid args\n')
                return

        else:
            # AddReg_chains = {'register-store': {'register-adder': [Chain, Chain, Chain...]}}
            chain_list = AddReg_chains.get(dest_reg, {}).get(adder_reg, None)

        if not chain_list:
            print('\nNo chains found for "AddReg {0} {1}"\n'.format(dest_reg, adder_reg))
            return

        if len(items) == 3:
            if items[2].lower() == 'all':
                max_to_show = len(chain_list)

            elif items[2].isdigit():
                max_to_show = min(len(chain_list), int(items[2]))

            else:
                print('Invalid param for <max-chains-to-show> : {0}'.format(items[2]))
                return

        else:
            max_to_show = 3

        self.serve_chain_list(chain_list, list_name='AddReg[{0}][{1}]'.format(dest_reg, adder_reg), register_to_preserve=dest_reg, max_to_show=max_to_show)

    def complete_AddReg(self, text, line, begidx, endidx):
        tmp = line.split(' ')
        if len(tmp) == 3:
            line = ' '.join(tmp[0:1] + tmp[2:])

        return self.register_completion(text, line, begidx, endidx)

    def help_AddReg(self):
        print('\n"AddReg" command\n')
        print('\tUsage:        AddReg <dst-register> <adder-register | constant> [max-chains-to-show | all]')
        print('\tExamples:     AddReg eax ebx')
        print('\t              AddReg eax ebx 10')
        print('\t              AddReg eax ebx all\n')
        print('\t              AddReg eax 0x4 all\n')
        print('\tDescription:  Show gadget chains that sum the values of <dst-register> and <adder-register | constant> and\n' \
              '\t              store the result in <dst-register>.\n')

    def dump_best_ReadMem(self, filter_dst=None, filter_src=None):
        filter_present = ''

        if filter_dst:
            filter_present = self.color_good(' (filter value-register={0})'.format(filter_dst))

        elif filter_src:
            filter_present = self.color_good(' (filter mem-addr-register={0})'.format(filter_src))

        print('\nBest ReadMem operations{0}:'.format(filter_present))
        for info in self.stats['ReadMem']:
            # MemRead_chains = {'mem-addr-register': {'value-register': [Chain, Chain, Chain]}}
            chains = MemRead_chains.get(info[0], {}).get(info[1], None)
            if chains:
                if not filter_dst and not filter_src:
                    print('\tReadMem {0} {1}: {2} chains, first chain with rank {3}'.format(info[1], info[0], len(chains), self.color_grade(chains[0].grade)))

                elif filter_dst:
                    if info[1] == filter_dst:
                        print('\tReadMem {0} {1}: {2} chains, first chain with rank {3}'.format(info[1], info[0], len(chains), self.color_grade(chains[0].grade)))

                elif filter_src:
                    if info[0] == filter_src:
                        print('\tReadMem {0} {1}: {2} chains, first chain with rank {3}'.format(info[1], info[0], len(chains), self.color_grade(chains[0].grade)))
        
        print('')

    def dump_best_StoreMem(self, filter_dst=None, filter_src=None):
        filter_present = ''

        if filter_dst:
            filter_present = self.color_good(' (filter mem-addr-register={0})'.format(filter_dst))

        elif filter_src:
            filter_present = self.color_good(' (filter value-register={0})'.format(filter_src))

        print('\nBest StoreMem operations{0}:'.format(filter_present))
        for info in self.stats['StoreMem']:
            # MemStore_chains = {'mem-addr-register': {'value-register': [Chain, Chain, Chain]}}
            chains = MemStore_chains.get(info[0], {}).get(info[1], None)
            if chains:
                if not filter_dst and not filter_src:
                    print('\tStoreMem {0} {1}: {2} chains, first chain with rank {3}'.format(info[0], info[1], len(chains), self.color_grade(chains[0].grade)))

                elif filter_dst:
                    if info[0] == filter_dst:
                        print('\tStoreMem {0} {1}: {2} chains, first chain with rank {3}'.format(info[0], info[1], len(chains), self.color_grade(chains[0].grade)))

                elif filter_src:
                    if info[1] == filter_src:
                        print('\tStoreMem {0} {1}: {2} chains, first chain with rank {3}'.format(info[0], info[1], len(chains), self.color_grade(chains[0].grade)))
        
        print('')

    def dump_best_SubReg(self, filter_dst=None, filter_src=None):
        filter_present = ''

        if filter_dst:
            filter_present = self.color_good(' (filter dst-register={0})'.format(filter_dst))

        elif filter_src:
            filter_present = self.color_good(' (filter subtractor-register={0})'.format(filter_src))

        print('\n{0}'.format(self.color_good('Remember: sub eax, ebx == add eax, neg(ebx)')))

        print('\nBest SubReg operations{0}:'.format(filter_present))
        for info in self.stats['SubReg']:
            chains = []
            if info[1] == '<constant>':
                for key in SubReg_chains.get(info[0], {}).keys():
                    if key.startswith('0x'):
                        chains += SubReg_chains.get(info[0], {}).get(key, [])

            else:
                # SubReg_chains = {'register-store': {'register-subber': [Chain, Chain, Chain...]}}
                chains = SubReg_chains.get(info[0], {}).get(info[1], None)

            if chains:
                comment = ''
                if info[0] in ['esp', 'rsp']:
                    comment = self.color_good(' (stack pivot)')

                elif info[1] in ['esp', 'rsp']:
                    comment = self.color_good(' (get stack ptr)')

                elif info[1] in ['ebp', 'rbp']:
                    comment = self.color_medium(' (get stack ptr)')

                if not filter_dst and not filter_src:
                    if info[1] != '<constant>':
                        print('\tSubReg {0} {1}{2}: {3} chains, first chain with rank {4}'.format(info[0], info[1], comment, len(chains), self.color_grade(chains[0].grade)))

                    else:
                        print('\tSubReg {0} {1}{2}: {3} chains'.format(info[0], info[1], comment, len(chains)))

                elif filter_dst:
                    if info[0] == filter_dst:
                        if info[1] != '<constant>':
                            print('\tSubReg {0} {1}{2}: {3} chains, first chain with rank {4}'.format(info[0], info[1], comment, len(chains), self.color_grade(chains[0].grade)))

                        else:
                            print('\tSubReg {0} {1}{2}: {3} chains'.format(info[0], info[1], comment, len(chains)))

                elif filter_src:
                    if info[1] == filter_src:
                        if info[1] != '<constant>':
                            print('\tSubReg {0} {1}{2}: {3} chains, first chain with rank {4}'.format(info[0], info[1], comment, len(chains), self.color_grade(chains[0].grade)))

                        else:
                            print('\tSubReg {0} {1}{2}: {3} chains'.format(info[0], info[1], comment, len(chains)))
                
        print('')

    def dump_best_AddReg(self, filter_dst=None, filter_src=None):
        filter_present = ''

        if filter_dst:
            filter_present = self.color_good(' (filter dst-register={0})'.format(filter_dst))

        elif filter_src:
            filter_present = self.color_good(' (filter adder-register={0})'.format(filter_src))


        print('\n{0}'.format(self.color_good('Remember: add eax, ebx == sub eax, neg(ebx)')))
        print('\nBest AddReg operations{0}:'.format(filter_present))
        for info in self.stats['AddReg']:
            # AddReg_chains = {'register-store': {'register-adder': [Chain, Chain, Chain...]}}
            chains = []
            if info[1] == '<constant>':
                for key in AddReg_chains.get(info[0], {}).keys():
                    if key.startswith('0x'):
                        chains += AddReg_chains.get(info[0], {}).get(key, [])

            else:
                chains = AddReg_chains.get(info[0], {}).get(info[1], None)

            if chains:
                comment = ''
                if info[0] in ['esp', 'rsp']:
                    comment = self.color_good(' (stack pivot)')

                elif info[1] in ['esp', 'rsp']:
                    comment = self.color_good(' (get stack ptr)')

                elif info[1] in ['ebp', 'rbp']:
                    comment = self.color_medium(' (get stack ptr)')

                if not filter_dst and not filter_src:
                    if info[1] != '<constant>':
                        print('\tAddReg {0} {1}{2}: {3} chains, first chain with rank {4}'.format(info[0], info[1], comment, len(chains), self.color_grade(chains[0].grade)))

                    else:
                        print('\tAddReg {0} {1}{2}: {3} chains'.format(info[0], info[1], comment, len(chains)))
                
                elif filter_dst:
                    if info[0] == filter_dst:
                        if info[1] != '<constant>':
                            print('\tAddReg {0} {1}{2}: {3} chains, first chain with rank {4}'.format(info[0], info[1], comment, len(chains), self.color_grade(chains[0].grade)))

                        else:
                            print('\tAddReg {0} {1}{2}: {3} chains'.format(info[0], info[1], comment, len(chains)))

                elif filter_src:
                    if info[1] == filter_src:
                        if info[1] != '<constant>':
                            print('\tAddReg {0} {1}{2}: {3} chains, first chain with rank {4}'.format(info[0], info[1], comment, len(chains), self.color_grade(chains[0].grade)))

                        else:
                            print('\tAddReg {0} {1}{2}: {3} chains'.format(info[0], info[1], comment, len(chains)))
        
        print('')

    def dump_best_ZeroReg(self):
        print('\nBest ZeroReg operations:')
        for info in self.stats['ZeroReg']:
            # ZeroReg_chains = {'register-to-zeroe': [Chain, Chain, Chain...]}
            chains = ZeroReg_chains.get(info[0], None)
            if chains:
                print('\tZeroReg {0}: {1} chains, first chain with rank {2}'.format(info[0], len(chains), self.color_grade(chains[0].grade)))
        
        print('')

    def dump_best_MoveReg(self, filter_dst=None, filter_src=None):
        filter_present = ''

        if filter_dst:
            filter_present = self.color_good(' (filter dst-register={0})'.format(filter_dst))

        elif filter_src:
            filter_present = self.color_good(' (filter src-register={0})'.format(filter_src))

        print('\nBest MoveReg operations{0}:'.format(filter_present))
        for info in self.stats['MoveReg']:
            # MoveReg_chains = {'register-src': {'register-dst': [Chain, Chain, Chain...]}}
            chains = MoveReg_chains.get(info[0], {}).get(info[1], None)
            if chains:
                comment = ''
                if info[1] in ['esp', 'rsp']:
                    comment = self.color_good(' (stack pivot)')

                elif info[0] in ['esp', 'rsp']:
                    comment = self.color_good(' (get stack ptr)')

                elif info[0] in ['ebp', 'rbp']:
                    comment = self.color_medium(' (get stack ptr)')

                if not filter_dst and not filter_src:
                    print('\tMoveReg {0} {1}{2}: {3} chains, first chain with rank {4}'.format(info[1], info[0], comment, len(chains), self.color_grade(chains[0].grade)))

                elif filter_dst:
                    if info[1] == filter_dst:
                        print('\tMoveReg {0} {1}{2}: {3} chains, first chain with rank {4}'.format(info[1], info[0], comment, len(chains), self.color_grade(chains[0].grade)))

                elif filter_src:
                    if info[0] == filter_src:
                        print('\tMoveReg {0} {1}{2}: {3} chains, first chain with rank {4}'.format(info[1], info[0], comment, len(chains), self.color_grade(chains[0].grade)))
        
        print('')

    def do_MoveReg(self, in_args):
        if not in_args:
            self.dump_best_MoveReg()
            return

        items = in_args.split(' ')

        if len(items) == 1:
            if items[0] not in ALL_KNOWN_REGISTERS:
                print('\nInvalid args\n')
                return

            self.dump_best_MoveReg(filter_dst=items[0])
            return

        elif len(items) == 2:
            if items[0] == '*' and items[1] == '*':
                self.dump_best_MoveReg()
                return

            elif items[0] == '*' and items[1] in ALL_KNOWN_REGISTERS:
                self.dump_best_MoveReg(filter_src=items[1])
                return

            elif items[0] in ALL_KNOWN_REGISTERS and items[1] == '*':
                self.dump_best_MoveReg(filter_dst=items[0])
                return

            # will continue

        elif len(items) > 3 or (len(items) == 3 and '*' in items):
            print('\nInvalid args\n')
            return

        dest_reg = items[0]
        src_reg = items[1]

        # MoveReg_chains = {'register-src': {'register-dst': [Chain, Chain, Chain...]}}
        chain_list = MoveReg_chains.get(src_reg, {}).get(dest_reg, None)

        if not chain_list:
            print('\nNo chains found for "MoveReg {0} {1}"\n'.format(dest_reg, src_reg))
            return

        if len(items) == 3:
            if items[2].lower() == 'all':
                max_to_show = len(chain_list)

            elif items[2].isdigit():
                max_to_show = min(len(chain_list), int(items[2]))

            else:
                print('Invalid param for <max-chains-to-show> : {0}'.format(items[2]))
                return

        else:
            max_to_show = 3

        self.serve_chain_list(chain_list, list_name='MoveReg[{0}][{1}]'.format(dest_reg, src_reg), register_to_preserve=dest_reg, max_to_show=max_to_show)

    def complete_MoveReg(self, text, line, begidx, endidx):
        tmp = line.split(' ')
        if len(tmp) == 3:
            line = ' '.join(tmp[0:1] + tmp[2:])

        return self.register_completion(text, line, begidx, endidx)

    def help_MoveReg(self):
        print('\n"MoveReg" command\n')
        print('\tUsage:        MoveReg <dst-register> <src-register> [max-chains-to-show | all]')
        print('\tExamples:     MoveReg eax ebx')
        print('\t              MoveReg eax ebx 10')
        print('\t              MoveReg eax ebx all\n')
        print('\tDescription:  Show gadget chains that make the value in <src-register> go to <dst-register>\n')

    def constant_contains_badchar(self, const_value: int):
        global BAD_CHARS

        if GADGETS_ARCH_BITS == 64:
            data = struct.pack('<Q', const_value)

        else:
            data = struct.pack('<I', const_value)
        
        for bad_char in BAD_CHARS:
            if bad_char in data:
                return True
        
        return False


    def get_random_without_badchar(self):
        global GADGETS_ARCH_BITS
        global BAD_CHARS

        available_bytes = bytearray()
        for i in range(0, 0xff+1):
            if i not in BAD_CHARS:
                available_bytes += bytearray(i.to_bytes(1, 'big'))

        if len(available_bytes) == 0:
            raise Exception('All bytes are bad chars')

        num_bytes = 4
        if GADGETS_ARCH_BITS == 64:
            num_bytes = 8

        constant = bytearray()
        for i in range(num_bytes):
            constant += bytearray(random.choice(available_bytes).to_bytes(1, 'big'))

        constant = bytes(constant)

        if num_bytes == 4:
            return struct.unpack('<I', constant)[0]

        else:
            return struct.unpack('<Q', constant)[0]

    def derive_sub_without_badchars(self, const_value):
        for i in range(100000):
            if i != 0:
                initial_value = self.get_random_without_badchar()

            else:
                initial_value = 0x70707070
                
                if GADGETS_ARCH_BITS == 64:
                    initial_value = 0x7070707070707070

                if self.constant_contains_badchar(initial_value):
                    initial_value = self.get_random_without_badchar()

            if initial_value == None:
                return None, None

            if GADGETS_ARCH_BITS == 64:
                complement = ctypes.c_uint64(const_value + initial_value).value
                sub_correct = ctypes.c_uint64(complement - initial_value).value == const_value

            else:
                complement = ctypes.c_uint32(const_value + initial_value).value
                sub_correct = ctypes.c_uint32(complement - initial_value).value == const_value

            if not self.constant_contains_badchar(complement) and sub_correct:
                return complement, initial_value

        return None, None

    def derive_sum_without_badchars(self, const_value):
        for i in range(100000):
            if i != 0:
                initial_value = self.get_random_without_badchar()

            else:
                initial_value = 0x70707070
                
                if GADGETS_ARCH_BITS == 64:
                    initial_value = 0x7070707070707070

                if self.constant_contains_badchar(initial_value):
                    initial_value = self.get_random_without_badchar()

            if initial_value == None:
                return None, None

            if GADGETS_ARCH_BITS == 64:
                complement = ctypes.c_uint64(const_value - initial_value).value
                sum_correct = ctypes.c_uint64(initial_value + complement).value == const_value

            else:
                complement = ctypes.c_uint32(const_value - initial_value).value
                sum_correct = ctypes.c_uint32(initial_value + complement).value == const_value

            if not self.constant_contains_badchar(complement) and sum_correct:
                return initial_value, complement

        return None, None

    def hex_converter(self, value):
        if GADGETS_ARCH_BITS == 64:
            return '{0:#018x}'.format(value)

        return '{0:#010x}'.format(value)

    def dump_best_LoadConst(self):
        print('\nBest LoadConst operations:')
        for info in self.stats['LoadConst']:
            # LoadConstAuxiliary_chains = {'register-to-modify': {'auxiliary-type': [Chain, Chain, Chain...]}}
            chains = LoadConstAuxiliary_chains.get(info[0], {}).get('just-load', None)
            if chains:
                print('\tLoadConst {0}: {1} chains, first chain with rank {2}'.format(info[0], len(chains), self.color_grade(chains[0].grade)))
        
        print('')

        print('\nBest LoadConst operations avoiding bad chars:')
        for info in self.stats['LoadConstAvoidBadChar']:
            chains = []

            for auxiliary_type in ['neg-after-load', 'not-after-load', 'add-after-load', 'sub-after-load']:
                chains += LoadConstAuxiliary_chains.get(info[0], {}).get(auxiliary_type, [])

            if chains:
                print('\tLoadConst {0}: {1} chains'.format(info[0], len(chains)))

        print('')

    def complete_LoadConst(self, text, line, begidx, endidx):
        return self.register_completion(text, line, begidx, endidx)

    def help_LoadConst(self):
        print('\n"LoadConst" command\n')
        print('\tUsage:        LoadConst <register-to-store> <constant-value> [max-chains-to-show | all]')
        print('\tExamples:     LoadConst eax 0xa')
        print('\t              LoadConst eax 10')
        print('\t              LoadConst eax 10 5')
        print('\t              LoadConst eax 0xa all\n')
        print('\tDescription:  Show gadget chains that load the <constant-value> into <register-to-store>.\n' \
              '\t              If bad chars are found in the constant, it will try to automatically create\n'\
              '\t              a chain that avoids bad chars.\n')

    def do_LoadConst(self, in_args):
        if not in_args:
            self.dump_best_LoadConst()
            return

        items = in_args.split(' ')

        if len(items) < 2:
            print('You must specify both the destination register and the constant.\n')
            return

        elif len(items) > 3:
            print('Invalid args\n')
            return

        dest_reg = items[0]
        constant_value_text = items[1]

        try:
            if constant_value_text.startswith('0x'):
                constant_value = int(constant_value_text, 16)

            elif constant_value_text.isdigit():
                constant_value = int(constant_value_text)

            else:
                print('Invalid args')
                return

        except:
            print('Invalid args')
            return
            
        if self.constant_contains_badchar(constant_value):
            # LoadConstAuxiliary_chains = {'register-to-modify': {'auxiliary-type': [Chain, Chain, Chain...]}}
            chain_list = []
            sum_operator_1, sum_operator_2 = self.derive_sum_without_badchars(constant_value)
            sub_operator_1, sub_operator_2 = self.derive_sub_without_badchars(constant_value)

            for auxiliary_type in LoadConstAuxiliary_chains.get(dest_reg, {}).keys():
                tmp_list = copy.deepcopy(LoadConstAuxiliary_chains[dest_reg][auxiliary_type])

                for chain in tmp_list:
                    fixed_chain = False

                    for gadget in chain.gadgets:
                        if auxiliary_type == 'neg-after-load':
                            if gadget.gadget_type != 'constant':
                                continue

                            if GADGETS_ARCH_BITS == 64:
                                negate_constant_value = self.hex_converter(ctypes.c_uint64(0 - constant_value).value)

                            else:
                                negate_constant_value = self.hex_converter(ctypes.c_uint32(0 - constant_value).value)

                            if not self.constant_contains_badchar(int(negate_constant_value, 16)):
                                gadget.address = negate_constant_value
                                gadget.comments = 'CONSTANT neg({0}) to avoid badchars'.format(constant_value_text)
                                fixed_chain = True

                        elif auxiliary_type == 'not-after-load':
                            if gadget.gadget_type != 'constant':
                                continue

                            if GADGETS_ARCH_BITS == 64:
                                negate_constant_value = self.hex_converter(ctypes.c_uint64(~constant_value).value)

                            else:
                                negate_constant_value = self.hex_converter(ctypes.c_uint32(~constant_value).value)

                            if not self.constant_contains_badchar(int(negate_constant_value, 16)):
                                gadget.address = negate_constant_value
                                gadget.comments = 'CONSTANT not({0}) to avoid badchars'.format(constant_value_text)
                                fixed_chain = True

                        elif auxiliary_type == 'add-after-load':
                            if None in [sum_operator_1, sum_operator_2]:
                                continue

                            if gadget.gadget_type != 'constant':
                                continue

                            if gadget.comments == 'CONSTANT1':
                                gadget.address = self.hex_converter(sum_operator_1)
                                gadget.comments = 'CONSTANT {0} ({1} - {2})'.format(self.hex_converter(sum_operator_1), constant_value_text, self.hex_converter(sum_operator_2))

                            elif gadget.comments == 'CONSTANT2':
                                gadget.address = self.hex_converter(sum_operator_2)
                                gadget.comments = 'CONSTANT {0} ({1} - {2})'.format(self.hex_converter(sum_operator_2), constant_value_text, self.hex_converter(sum_operator_1))
                                fixed_chain = True

                        elif auxiliary_type == 'sub-after-load':
                            if None in [sub_operator_1, sub_operator_2]:
                                continue

                            if gadget.gadget_type != 'constant':
                                continue

                            if gadget.comments == 'CONSTANT1':
                                gadget.address = self.hex_converter(sub_operator_1)
                                gadget.comments = 'CONSTANT {0} ({1} + {2})'.format(self.hex_converter(sub_operator_1), constant_value_text, self.hex_converter(sub_operator_2))

                            elif gadget.comments == 'CONSTANT2':
                                gadget.address = self.hex_converter(sub_operator_2)
                                gadget.comments = 'CONSTANT {0} ({1} + {2})'.format(self.hex_converter(sub_operator_2), constant_value_text, self.hex_converter(sub_operator_1))
                                fixed_chain = True

                    if fixed_chain:
                        chain_list.append(chain)

        else:
            chain_list = []
            tmp_list = copy.deepcopy(LoadConstAuxiliary_chains.get(dest_reg, {}).get('just-load', []))

            for chain in tmp_list:
                fixed_chain = False

                for gadget in chain.gadgets:
                    if gadget.comments == 'CONSTANT1':
                        gadget.address = self.hex_converter(constant_value)
                        gadget.comments = 'CONSTANT {0}'.format(constant_value_text)
                        fixed_chain = True

                chain_list.append(chain)

        chain_list = sorted(chain_list, key=lambda x: x.grade)

        if not chain_list:
            print('\nNo chains found for "LoadConst {0} {1}"\n'.format(dest_reg, constant_value_text))
            return

        if len(items) == 3:
            if items[2].lower() == 'all':
                max_to_show = len(chain_list)

            elif items[2].isdigit():
                max_to_show = min(len(chain_list), int(items[2]))

            else:
                print('Invalid param for <max-chains-to-show> : {0}'.format(items[2]))
                return

        else:
            max_to_show = 3

        self.serve_chain_list(chain_list, list_name='LoadConst[{0}][{1}]'.format(dest_reg, constant_value_text), register_to_preserve=dest_reg, max_to_show=max_to_show)

    def do_ZeroReg(self, in_args):
        if not in_args:
            self.dump_best_ZeroReg()
            return

        items = in_args.split(' ')

        if len(items) > 2:
            print('Invalid args\n')
            return

        register = items[0]
        chain_list = ZeroReg_chains.get(register, None)

        if not chain_list:
            print('\nNo chains found for "ZeroReg {0}"\n'.format(register))
            return

        if len(items) == 2:
            if items[1].lower() == 'all':
                max_to_show = len(chain_list)

            elif items[1].isdigit():
                max_to_show = min(len(chain_list), int(items[1]))

            else:
                print('Invalid param for <max-chains-to-show> : {0}'.format(items[1]))
                return

        else:
            max_to_show = 3
        
        
        self.serve_chain_list(chain_list, list_name='ZeroReg[{0}]'.format(register), register_to_preserve=register, max_to_show=max_to_show)

    def complete_ZeroReg(self, text, line, begidx, endidx):
        return self.register_completion(text, line, begidx, endidx)
        
    def help_ZeroReg(self):
        print('\n"ZeroReg" command\n')
        print('\tUsage:        ZeroReg <register-to-zero> [max-chains-to-show | all]')
        print('\tExamples:     ZeroReg eax')
        print('\t              ZeroReg eax 10')
        print('\t              ZeroReg eax all\n')
        print('\tDescription:  Show gadget chains that zeroe a given register\n')

    def complete_calc(self, text, line, begidx, endidx):
        completions = ['neg', 'not']
        
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] + ' ' for s in completions if s.startswith(mline)]

    def help_calc(self):
        print('\n"calc" command\n')
        print('\tUsage:        calc <operation> <argument>')
        print('\tOperations:   neg, not\n')
        print('\tExamples:     calc neg 0x1')
        print('\t              calc neg -20')
        print('\t              calc not 0x1')
        print('\t              calc not -20\n')

        print('\tDescription:  Performs some operation and shows the result\n')

    def parse_integer(self, value_str):
        try:
            if value_str.startswith('0x') or value_str.startswith('-0x'):
                return int(value_str, 16)

            elif value_str.isdigit() or (value_str[0] == '-' and value_str[1:].isdigit()):
                return int(value_str)

        except:
            pass

        return None

    def effective_perform_not(self, number_str):
        number = self.parse_integer(number_str)
        if number != None:
            emu = x86Emulator(bits=GADGETS_ARCH_BITS)

            ax = 'eax'
            if GADGETS_ARCH_BITS == 64:
                ax = 'rax'

            emu.set_register_value(ax, number)
            emu.exec_instruction(x86Instruction('not {0}'.format(ax)))

            result = emu.get_register_value(ax)

            print('\nnot({0}) is {1} in hex'.format(number_str, self.hex_converter(result)))
            print('not({0}) is {1} in decimal\n'.format(number_str, result))
            return

        print('\nInvalid number: {0}\n'.format(number_str))

    def effective_perform_neg(self, number_str):
        number = self.parse_integer(number_str)
        if number != None:
            emu = x86Emulator(bits=GADGETS_ARCH_BITS)

            ax = 'eax'
            if GADGETS_ARCH_BITS == 64:
                ax = 'rax'

            emu.set_register_value(ax, number)
            emu.exec_instruction(x86Instruction('neg {0}'.format(ax)))

            result = emu.get_register_value(ax)

            print('\nneg({0}) is {1} in hex'.format(number_str, self.hex_converter(result)))
            print('neg({0}) is {1} in decimal\n'.format(number_str, result))
            return

        print('\nInvalid number: {0}\n'.format(number_str))

    def do_calc(self, in_args):
        items = in_args.split(' ')

        if not in_args or len(items) == 0:
            print('\nInvalid args\n')
            return

        if items[0] == 'neg':
            if len(items) != 2:
                print('\nInvalid args\n')
                return

            self.effective_perform_neg(items[1])
            return

        elif items[0] == 'not':
            if len(items) != 2:
                print('\nInvalid args\n')
                return

            self.effective_perform_not(items[1])
            return

        else:
            print('\nInvalid args\n')
            return

    def register_completion(self, text, line, begidx, endidx):
        if GADGETS_ARCH_BITS == 64:
            completions = ALL_KNOWN_REGISTERS

        else:
            completions = KNOWN_REGISTERS_32

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] + ' ' for s in completions if s.startswith(mline)]

    def emptyline(self):
        pass

    def cleanup(self):
        print('Cleaning up')


def parse_integer(value_str):
    try:
        if value_str.startswith('0x') or value_str.startswith('-0x'):
            return int(value_str, 16)

        elif value_str.isdigit() or (value_str[0] == '-' and value_str[1:].isdigit()):
            return int(value_str)

    except:
        pass

    raise Exception('Unable to parse integer: {0}'.format(value_str))


def parse_badchars(badchars_str):
    try:
        bad_chars_tmp = ast.literal_eval("b'{0}'".format(badchars_str))
        return bytes(set(bad_chars_tmp))
    except:
        pass

    raise Exception('Unable to parse bad chars: {0}'.format(badchars_str))


def bytes_to_hex_escaped(data_bytes):
    hex_str = binascii.hexlify(data_bytes)
    hex_str = b' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))

    return ''.join(list(map(lambda x: '\\x{0}'.format(x), hex_str.decode().split(' '))))


def main():
    global BAD_CHARS
    global GADGETS_ARCH_BITS

    parser = argparse.ArgumentParser(description='SmartChainer arguments')

    parser.add_argument('--bad-chars', help="Bytes to avoid in gadget addresses. Example: --bad-chars='\\x00\\x0d\\x0a'", type=str)
    parser.add_argument('--base-address', help="Specify a base address for gadgets. "\
                                               "Examples: --base-address='0x1000' for positive offsets or --base-address='-0x1000' "\
                                               "for negative offsets", type=str, default='0x0')

    parser.add_argument('--arch', help='Specify the processor architecture of gadgets', choices=['x86', 'x64'], default='x86')

    parser.add_argument('--no-color', help='Disable colored output', action='store_true')

    parser.add_argument('gadgets_file', help='Text file with gadgets')

    args = parser.parse_args()


    if args.arch == 'x86':
        GADGETS_ARCH_BITS = 32

    elif args.arch == 'x64':
        GADGETS_ARCH_BITS = 64

    log_info('[+] Architecture: {0}'.format(args.arch))

    base_addr = 0
    if args.base_address:
        base_addr = parse_integer(args.base_address)

    bad_chars = b''
    if args.bad_chars:
        bad_chars = parse_badchars(args.bad_chars)

        if args.bad_chars.startswith('x'):
            log_info('[!] Have you specified the bad chars inside single quotes?')
            print('[!] These are the bad chars I understood you specified: {0}'.format(bytes_to_hex_escaped(bad_chars)))
            answer = input('[?] Is this correct? [y/N]: ')

            if answer.upper() != 'Y':
                log_info("[!] Try to specify bad chars inside single quotes. Example: --bad-chars='\\x00\\xff'")
                return 1
        
    BAD_CHARS = bad_chars

    t1 = time.time()

    if not os.path.isfile(args.gadgets_file):
        print('[-] File {0} not found\n'.format(args.gadgets_file))
        return

    gadgets = get_gadgets_from_file(args.gadgets_file, base_addr)

    if len(gadgets) == 0:
        log_info('[-] No gadgets were loaded. Aborting.')
        return 1

    log_info('[+] Loaded {0} gadgets'.format(len(gadgets)))

    gadgets = remove_duplicated_gadgets(gadgets)
    random.shuffle(gadgets)  # the shuffle will improve the percentage precision

    initialize_semantic_gadgets(gadgets)

    t2 = time.time()
    print('[+] Done! Load time: {0:.2f} seconds\n'.format(t2-t1))

    color = True
    if args.no_color or sys.platform == 'win32':
        color = False

    prompt = RopShell(color=color)

    try:
        prompt.cmdloop()
    except Exception as e:
        notify_exception(e)

    finally:
        prompt.cleanup()


if __name__ == '__main__':
    ret = main()
    sys.exit(ret)