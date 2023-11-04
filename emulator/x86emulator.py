import sys
import ctypes
import struct

MEM_READ  = 0x1 << 0
MEM_EXEC  = 0x1 << 1
MEM_WRITE = 0x1 << 2
REASON_UNMAPPED = 0x1 << 0x0
REASON_NOT_READABLE = 0x1 << 1
REASON_NOT_WRITEABLE = 0x1 << 2
REASON_FAR_FROM_SP = 0x1 << 3
INVALID_READ_DATA = 0xdead
DEFAULT_STACK_START_PAGE = 0x0075c000
DEFAULT_STACK_PTR = DEFAULT_STACK_START_PAGE + 0x2220
OPERATION_CALL = 0x1 << 4
OPERATION_JMP = 0x1 << 5
OPERATION_INTERRUPT = 0x1 << 6
OPERATION_SYSCALL = 0x1 << 7
OPERATION_DBGBREAK = 0x1 << 8

SEGMENT_REGISTER_DS = 0x1 << 0
SEGMENT_REGISTER_SS = 0x1 << 1
SEGMENT_REGISTER_ES = 0x1 << 2
SEGMENT_REGISTER_FS = 0x1 << 3
SEGMENT_REGISTER_GS = 0x1 << 4

class x86Instruction:
    NO_OPERAND_INSTRUCTIONS = ['ret', 'nop', 'leave', 'pushad', 'pushal', 'popad', 'popal', 'int', 'int3', 'syscall', 'endbr32', 'endbr64', 'vzeroupper']
    SINGLE_OPERAND_INSTRUCTIONS = ['push', 'pop', 'neg', 'not', 'inc', 'retn', 'dec', 'call', 'jmp', 'sete']
    DOUBLE_OPERAND_INSTRUCTIONS = ['mov', 'cmovne', 'movzx', 'movsxd', 'bsf', 'xor', 'add', 'adc', 'sub', 'or', 'and', 'cmp', 'xchg', 'test', 'lds', 'lss', 'les', 'lfs', 'lgs', 'lea', 'sbb', 'ror', 'rcr', 'rol', 'rcl', 'shl', 'sal', 'shr', 'sar']
    VARIABLE_OPERAND_INSTRUCTIONS = []  # ['sal']
    KNOWN_INSTRUCTIONS = NO_OPERAND_INSTRUCTIONS + SINGLE_OPERAND_INSTRUCTIONS + DOUBLE_OPERAND_INSTRUCTIONS + VARIABLE_OPERAND_INSTRUCTIONS

    def __init__(self, instruction_str):
        instruction_str = instruction_str.strip().lower()
        self.num_operands = 0
        self.first_operand = None
        self.second_operand = None

        if instruction_str in x86Instruction.NO_OPERAND_INSTRUCTIONS:
            self.mnemonic = instruction_str
            return

        sep = instruction_str.find(' ')
        if sep == -1:
            raise Exception('Unknown instruction: {0}'.format(instruction_str))

        tmp = instruction_str[:sep]

        if tmp not in x86Instruction.KNOWN_INSTRUCTIONS:
            raise Exception('Unknown instruction: {0}'.format(instruction_str))

        self.mnemonic = tmp
        tmp = instruction_str[sep:].strip()
        sep = tmp.find(',')

        if sep != -1 and self.mnemonic in x86Instruction.SINGLE_OPERAND_INSTRUCTIONS:
            raise Exception('Unknown instruction: {0}'.format(instruction_str))

        if sep == -1 and self.mnemonic in x86Instruction.DOUBLE_OPERAND_INSTRUCTIONS:
            raise Exception('Unknown instruction: {0}'.format(instruction_str))

        if sep == -1:
            self.first_operand = tmp.strip()

            if self.first_operand.isdigit():
                self.first_operand = hex(int(self.first_operand))

            self.num_operands = 1

        else:
            self.first_operand = tmp[:sep].strip()
            if self.first_operand.isdigit():
                self.first_operand = hex(int(self.first_operand))

            self.second_operand = tmp[sep+1:].strip()
            if self.second_operand.isdigit():
                self.second_operand = hex(int(self.second_operand))

            self.num_operands = 2

    def __str__(self):
        if self.num_operands == 0:
            return self.mnemonic

        elif self.num_operands == 1:
            return '{0} {1}'.format(self.mnemonic, self.first_operand)

        elif self.num_operands == 2:
            return '{0} {1}, {2}'.format(self.mnemonic, self.first_operand, self.second_operand)


class x86Emulator:
    def __init__(self, bits=32):
        if bits not in [32, 64]:
            raise Exception('Invalid arch')

        self.BITS = bits

        self.KNOWN_REGISTERS =  ['eax', 'ax', 'ah', 'al']
        self.KNOWN_REGISTERS += ['ebx', 'bx', 'bh', 'bl']
        self.KNOWN_REGISTERS += ['ecx', 'cx', 'ch', 'cl']
        self.KNOWN_REGISTERS += ['edx', 'dx', 'dh', 'dl']
        self.KNOWN_REGISTERS += ['esi', 'si']
        self.KNOWN_REGISTERS += ['edi', 'di']
        self.KNOWN_REGISTERS += ['esp', 'sp']
        self.KNOWN_REGISTERS += ['ebp', 'bp']

        if self.BITS == 64:
            self.KNOWN_REGISTERS += ['rsp', 'rbp']
            self.KNOWN_REGISTERS += ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi']
            self.KNOWN_REGISTERS += ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
            self.KNOWN_REGISTERS += ['r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']
            self.KNOWN_REGISTERS += ['r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']
            self.KNOWN_REGISTERS += ['r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']

        self.DEFAULT_STACK_START_PAGE = 0x0075c000

        if self.BITS == 64:
            self.DEFAULT_STACK_START_PAGE = 0x7fffff880075c000

        self.DEFAULT_STACK_PTR = self.DEFAULT_STACK_START_PAGE + 0x2220
        self.init_memory()
        self.map_stack()
        self.set_registers_default_initial_state()
        self.initialize_exceptions()

        self.fail_mem_operation_far_from_stack_ptr = False

    def fail_mem_op_far_from_sp(self, flag):
        self.fail_mem_operation_far_from_stack_ptr = flag

    def get_default_register_size_bytes(self):
        return int(self.BITS / 8)

    def initialize_exceptions(self):
        self.exceptions = {
            'memory': {},
            'deviation': [],
            'segment': []
        }

        self.total_exceptions_count = 0
        self.different_exceptions_count = 0
        
    def init_memory(self):
        self.memory = {}
        self.memory_flags = {}
        self.memory_write_count = 0
        self.memory_write_list = []
        self.map_new_stack_on_maperror = False

    def map_new_stack_on_map_error(self, flag):
        self.map_new_stack_on_maperror = flag

    def map_stack(self):
        self.stack_page_start = self.DEFAULT_STACK_START_PAGE
        self.stack_num_pages = 3

        for i in range(self.stack_num_pages):
            self.map_page(self.stack_page_start + (i * 0x1000), MEM_READ | MEM_WRITE)
    
    def map_page(self, address, flags):
        address = address & 0xfffffffffffff000

        if self.memory.get(address) != None:
            raise Exception('Already mapped memory')

        self.memory[address] = bytearray(b'\xEF' * 0x1000)
        self.memory_flags[address] = flags

    def notify_segment_register_exception(self, segment_register):
        self.exceptions['segment'].append(segment_register)
        self.different_exceptions_count += 1
        self.total_exceptions_count += 1

    def notify_flow_deviation_exception(self, operation):
        self.exceptions['deviation'].append(operation)
        self.different_exceptions_count += 1
        self.total_exceptions_count += 1

    def notify_memory_exception(self, page, address, operation, reason):
        different_exception_happened = False

        if self.exceptions['memory'].get(page) == None:
            self.exceptions['memory'][page] = {}
            different_exception_happened = True

        if self.exceptions['memory'][page].get(operation) == None:
            self.exceptions['memory'][page][operation] = {}
            different_exception_happened = True

        if self.exceptions['memory'][page][operation].get(reason) == None:
            self.exceptions['memory'][page][operation][reason] = []
            different_exception_happened = True

        self.exceptions['memory'][page][operation][reason].append(address)
        self.total_exceptions_count += 1

        if different_exception_happened:
            self.different_exceptions_count += 1

    def write_mem(self, address, data):
        for i, b in enumerate(data):
            addr_to_write = address + i
            page = addr_to_write & 0xfffffffffffff000

            if not self.is_memory_mapped(page):
                if self.map_new_stack_on_maperror:
                    stack_page = self.get_stack_pointer_value() & 0xfffffffffffff000

                    if page == stack_page:
                        self.map_page(page, MEM_READ | MEM_WRITE)

                    else:
                        self.notify_memory_exception(page, addr_to_write, MEM_WRITE, REASON_UNMAPPED)
                        return None

                else:
                    self.notify_memory_exception(page, addr_to_write, MEM_WRITE, REASON_UNMAPPED)
                    return None

            if self.memory_flags[page] & MEM_WRITE == 0:
                self.notify_memory_exception(page, addr_to_write, MEM_WRITE, REASON_NOT_WRITEABLE)
                return None

            if self.fail_mem_operation_far_from_stack_ptr == True:
                if self.is_addr_far_from_sp(address):
                    self.notify_memory_exception(page, addr_to_write, MEM_WRITE, REASON_FAR_FROM_SP)
                    return None

            offset = addr_to_write & 0x0000000000000fff
            self.memory[page][offset] = b
            self.memory_write_count += 1
            self.memory_write_list.append({'page': page, 'offset': offset, 'byte': b})

    def is_addr_far_from_sp(self, address):
        sp_value = self.get_stack_pointer_value()
        sp_page = sp_value & 0xfffffffffffff000
        near_pages = [sp_page - 0x1000, sp_page, sp_page + 0x1000]

        addr_page = address & 0xfffffffffffff000

        return addr_page not in near_pages


    def read_mem(self, address, size):
        data = bytearray()

        for i in range(size):
            addr_to_read = address + i
            page = addr_to_read & 0xfffffffffffff000

            if not self.is_memory_mapped(page):
                if self.map_new_stack_on_maperror:
                    stack_page = self.get_stack_pointer_value() & 0xfffffffffffff000

                    if page == stack_page:
                        self.map_page(page, MEM_READ | MEM_WRITE)

                    else:
                        self.notify_memory_exception(page, addr_to_read, MEM_READ, REASON_UNMAPPED)
                        return None

                else:
                    self.notify_memory_exception(page, addr_to_read, MEM_READ, REASON_UNMAPPED)
                    return None

            if self.memory_flags[page] & MEM_READ == 0:
                self.notify_memory_exception(page, addr_to_read, MEM_READ, REASON_NOT_READABLE)
                return None

            if self.fail_mem_operation_far_from_stack_ptr == True:
                if self.is_addr_far_from_sp(address):
                    self.notify_memory_exception(page, addr_to_read, MEM_READ, REASON_FAR_FROM_SP)
                    return None

            offset = addr_to_read & 0x0000000000000fff
            data += self.memory[page][offset].to_bytes(1, 'big')

        return data

    def unmap_page(self, address):
        address = address & 0xfffffffffffff000

        if self.memory.get(address) == None:
            raise Exception('Unmapped memory')

        del self.memory[address]
        del self.memory_flags[address]

    def is_memory_mapped(self, address):
        address = address & 0xfffffffffffff000
        return self.memory.get(address) != None

    def exec_instruction(self, parsed_instruction):
        if parsed_instruction.mnemonic == 'add':
            self.run_add(parsed_instruction)

        elif parsed_instruction.mnemonic == 'pop':
            self.run_pop(parsed_instruction)

        elif parsed_instruction.mnemonic == 'mov':
            self.run_mov(parsed_instruction)

        elif parsed_instruction.mnemonic == 'cmovne':
            self.run_cmovne(parsed_instruction)

        elif parsed_instruction.mnemonic == 'movzx':
            self.run_movzx(parsed_instruction)

        elif parsed_instruction.mnemonic == 'movsxd':
            self.run_movsxd(parsed_instruction)

        elif parsed_instruction.mnemonic == 'bsf':
            self.run_bsf(parsed_instruction)
            
        elif parsed_instruction.mnemonic == 'ret':
            self.run_ret(parsed_instruction)

        elif parsed_instruction.mnemonic == 'retn':
            self.run_retn(parsed_instruction)

        elif parsed_instruction.mnemonic == 'push':
            self.run_push(parsed_instruction)

        elif parsed_instruction.mnemonic == 'nop':
            self.run_nop(parsed_instruction)

        elif parsed_instruction.mnemonic == 'endbr64':
            self.run_endbr64(parsed_instruction)

        elif parsed_instruction.mnemonic == 'endbr32':
            self.run_endbr32(parsed_instruction)

        elif parsed_instruction.mnemonic == 'vzeroupper':
            self.run_vzeroupper(parsed_instruction)

        elif parsed_instruction.mnemonic == 'adc':
            self.run_adc(parsed_instruction)

        elif parsed_instruction.mnemonic == 'or':
            self.run_or(parsed_instruction)

        elif parsed_instruction.mnemonic == 'xor':
            self.run_xor(parsed_instruction)

        elif parsed_instruction.mnemonic == 'and':
            self.run_and(parsed_instruction)

        elif parsed_instruction.mnemonic == 'inc':
            self.run_inc(parsed_instruction)

        elif parsed_instruction.mnemonic == 'sub':
            self.run_sub(parsed_instruction)

        elif parsed_instruction.mnemonic == 'dec':
            self.run_dec(parsed_instruction)

        elif parsed_instruction.mnemonic == 'cmp':
            self.run_cmp(parsed_instruction)

        elif parsed_instruction.mnemonic == 'neg':
            self.run_neg(parsed_instruction)

        elif parsed_instruction.mnemonic == 'xchg':
            self.run_xchg(parsed_instruction)

        elif parsed_instruction.mnemonic == 'test':
            self.run_test(parsed_instruction)

        elif parsed_instruction.mnemonic == 'sete':
            self.run_sete(parsed_instruction)

        elif parsed_instruction.mnemonic == 'call':
            self.run_call(parsed_instruction)

        elif parsed_instruction.mnemonic == 'int':
            self.run_int(parsed_instruction)

        elif parsed_instruction.mnemonic == 'syscall':
            self.run_syscall(parsed_instruction)
        
        elif parsed_instruction.mnemonic == 'int3':
            self.run_dbgbreak(parsed_instruction)

        elif parsed_instruction.mnemonic == 'jmp':
            self.run_jmp(parsed_instruction)

        elif parsed_instruction.mnemonic == 'leave':
            self.run_leave(parsed_instruction)

        elif parsed_instruction.mnemonic == 'lds':
            self.run_lds(parsed_instruction)

        elif parsed_instruction.mnemonic == 'lss':
            self.run_lss(parsed_instruction)

        elif parsed_instruction.mnemonic == 'les':
            self.run_les(parsed_instruction)

        elif parsed_instruction.mnemonic == 'lfs':
            self.run_lfs(parsed_instruction)

        elif parsed_instruction.mnemonic == 'lgs':
            self.run_lgs(parsed_instruction)

        elif parsed_instruction.mnemonic == 'lea':
            self.run_lea(parsed_instruction)

        elif parsed_instruction.mnemonic == 'sbb':
            self.run_sbb(parsed_instruction)

        elif parsed_instruction.mnemonic == 'ror':
            self.run_ror(parsed_instruction)

        elif parsed_instruction.mnemonic == 'rcr':
            self.run_rcr(parsed_instruction)

        elif parsed_instruction.mnemonic == 'rol':
            self.run_rol(parsed_instruction)

        elif parsed_instruction.mnemonic == 'rcl':
            self.run_rcl(parsed_instruction)

        elif parsed_instruction.mnemonic in ['sal', 'shl']:
            self.run_shl(parsed_instruction)

        elif parsed_instruction.mnemonic == 'shr':
            self.run_shr(parsed_instruction)

        elif parsed_instruction.mnemonic == 'sar':
            self.run_sar(parsed_instruction)

        elif parsed_instruction.mnemonic in ['pushad', 'pushal']:
            self.run_pushad(parsed_instruction)

        elif parsed_instruction.mnemonic in ['popad', 'popal']:
            self.run_popad(parsed_instruction)

        elif parsed_instruction.mnemonic == 'not':
            self.run_not(parsed_instruction)

        else:
            raise Exception('Unknown instruction: {0}'.format(parsed_instruction))

    def run_not(self, not_instr):
        if not_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(not_instr.first_operand)

        elif '[' in not_instr.first_operand:
            current_value = self.dereference_operand_read(not_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(not_instr.first_operand))
    
        new_value = ~current_value

        if not_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(not_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if not_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(not_instr.first_operand, new_value)

        elif '[' in not_instr.first_operand:
            self.dereference_operand_store(not_instr.first_operand, new_value)

    def run_popad(self, popad_instr):
        if self.BITS == 64:
            raise Exception('Invalid instruction: {0}'.format(pushad_instr))

        self.exec_instruction(x86Instruction('pop edi'))
        self.exec_instruction(x86Instruction('pop esi'))
        self.exec_instruction(x86Instruction('pop ebp'))
        self.exec_instruction(x86Instruction('pop ebx'))  # this one is the saved esp, but we should not restore esp
        self.exec_instruction(x86Instruction('pop ebx'))
        self.exec_instruction(x86Instruction('pop edx'))
        self.exec_instruction(x86Instruction('pop ecx'))
        self.exec_instruction(x86Instruction('pop eax'))


    def run_pushad(self, pushad_instr):
        if self.BITS == 64:
            raise Exception('Invalid instruction: {0}'.format(pushad_instr))

        esp = self.get_register_value('esp')
        self.exec_instruction(x86Instruction('push eax'))
        self.exec_instruction(x86Instruction('push ecx'))
        self.exec_instruction(x86Instruction('push edx'))
        self.exec_instruction(x86Instruction('push ebx'))
        self.exec_instruction(x86Instruction('push {0}'.format(hex(esp))))
        self.exec_instruction(x86Instruction('push ebp'))
        self.exec_instruction(x86Instruction('push esi'))
        self.exec_instruction(x86Instruction('push edi'))

    def run_sar(self, sar_instr):
        if sar_instr.second_operand.startswith('0x'):
            immediate = int(sar_instr.second_operand, 16)

        elif sar_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(sar_instr.second_operand)

        elif '[' in sar_instr.second_operand:
            immediate = self.dereference_operand_read(sar_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(sar_instr.second_operand))

        if sar_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(sar_instr.first_operand)

        elif '[' in sar_instr.first_operand:
            current_value = self.dereference_operand_read(sar_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(sar_instr.first_operand))
    
        new_value = current_value >> immediate

        if sar_instr.first_operand in self.KNOWN_REGISTERS:
            tmp = self.get_register_size_bits(sar_instr.first_operand)

        elif '[' in sar_instr.first_operand:
            if sar_instr.first_operand.strip().startswith('byte'):
                tmp = 8

            elif sar_instr.first_operand.strip().startswith('word'):
                tmp = 16

            elif sar_instr.first_operand.strip().startswith('dword'):
                tmp = 32

            elif sar_instr.first_operand.strip().startswith('qword'):
                tmp = 64

            else:
                tmp = self.BITS

        if(current_value & (1 << (tmp - 1)) != 0):
            new_value |= (1 << (tmp - 1))

        if sar_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(sar_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if sar_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(sar_instr.first_operand, new_value)

        elif '[' in sar_instr.first_operand:
            self.dereference_operand_store(sar_instr.first_operand, new_value)

    def run_shr(self, shr_instr):
        if shr_instr.second_operand.startswith('0x'):
            immediate = int(shr_instr.second_operand, 16)

        elif shr_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(shr_instr.second_operand)

        elif '[' in shr_instr.second_operand:
            immediate = self.dereference_operand_read(shr_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(shr_instr.second_operand))

        if shr_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(shr_instr.first_operand)

        elif '[' in shr_instr.first_operand:
            current_value = self.dereference_operand_read(shr_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(shr_instr.first_operand))
    
        new_value = current_value >> immediate

        if shr_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(shr_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if shr_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(shr_instr.first_operand, new_value)

        elif '[' in shr_instr.first_operand:
            self.dereference_operand_store(shr_instr.first_operand, new_value)

    def run_shl(self, shl_instr):
        if shl_instr.second_operand.startswith('0x'):
            immediate = int(shl_instr.second_operand, 16)

        elif shl_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(shl_instr.second_operand)

        elif '[' in shl_instr.second_operand:
            immediate = self.dereference_operand_read(shl_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(shl_instr.second_operand))

        if shl_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(shl_instr.first_operand)

        elif '[' in shl_instr.first_operand:
            current_value = self.dereference_operand_read(shl_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(shl_instr.first_operand))
    
        new_value = current_value << immediate

        if shl_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(shl_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if shl_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(shl_instr.first_operand, new_value)

        elif '[' in shl_instr.first_operand:
            self.dereference_operand_store(shl_instr.first_operand, new_value)

    def run_rcl(self, rol_instr):
        # rcl is implemented exactly as rol, without dealing with the carry bit
        # perfect correctness is not the priority - the side effects are acceptable
        if rol_instr.second_operand.startswith('0x'):
            immediate = int(rol_instr.second_operand, 16)

        elif rol_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(rol_instr.second_operand)

        else:
            raise Exception('Unknown operand: {0}'.format(rol_instr))

        if rol_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(rol_instr.first_operand)

        elif '[' in rol_instr.first_operand:
            current_value = self.dereference_operand_read(rol_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(rol_instr.first_operand))
    

        if rol_instr.first_operand in self.KNOWN_REGISTERS:
            new_value = self.rotate_left(current_value, immediate, self.get_register_size_bits(rol_instr.first_operand))
            register_size_bits = self.get_register_size_bits(rol_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if rol_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(rol_instr.first_operand, new_value)

        elif '[' in rol_instr.first_operand:
            if rol_instr.first_operand.strip().startswith('byte'):
                bits = 8

            elif rol_instr.first_operand.strip().startswith('word'):
                bits = 16

            elif rol_instr.first_operand.strip().startswith('dword'):
                bits = 32

            elif rol_instr.first_operand.strip().startswith('qword'):
                bits = 64

            else:
                bits = self.BITS

            new_value = self.rotate_left(current_value, immediate, bits)
            self.dereference_operand_store(rol_instr.first_operand, new_value)

    def run_rol(self, rol_instr):
        if rol_instr.second_operand.startswith('0x'):
            immediate = int(rol_instr.second_operand, 16)

        elif rol_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(rol_instr.second_operand)

        else:
            print()
            raise Exception('Unknown operand: {0}'.format(rol_instr.second_operand))

        if rol_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(rol_instr.first_operand)

        elif '[' in rol_instr.first_operand:
            current_value = self.dereference_operand_read(rol_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(rol_instr.first_operand))
    

        if rol_instr.first_operand in self.KNOWN_REGISTERS:
            new_value = self.rotate_left(current_value, immediate, self.get_register_size_bits(rol_instr.first_operand))
            register_size_bits = self.get_register_size_bits(rol_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if rol_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(rol_instr.first_operand, new_value)

        elif '[' in rol_instr.first_operand:
            if rol_instr.first_operand.strip().startswith('byte'):
                bits = 8

            elif rol_instr.first_operand.strip().startswith('word'):
                bits = 16

            elif rol_instr.first_operand.strip().startswith('dword'):
                bits = 32

            elif rol_instr.first_operand.strip().startswith('qword'):
                bits = 64

            else:
                bits = self.BITS

            new_value = self.rotate_left(current_value, immediate, bits)
            self.dereference_operand_store(rol_instr.first_operand, new_value)

    def run_rcr(self, ror_instr):
        # rcr is implemented exactly as ror, without dealing with the carry bit
        # perfect correctness is not the priority - the side effects are acceptable
        if ror_instr.second_operand.startswith('0x'):
            immediate = int(ror_instr.second_operand, 16)

        elif ror_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(ror_instr.second_operand)

        else:
            raise Exception('Unknown operand: {0}'.format(ror_instr.second_operand))

        if ror_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(ror_instr.first_operand)

        elif '[' in ror_instr.first_operand:
            current_value = self.dereference_operand_read(ror_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(ror_instr.first_operand))
    

        if ror_instr.first_operand in self.KNOWN_REGISTERS:
            new_value = self.rotate_right(current_value, immediate, self.get_register_size_bits(ror_instr.first_operand))
            register_size_bits = self.get_register_size_bits(ror_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if ror_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(ror_instr.first_operand, new_value)

        elif '[' in ror_instr.first_operand:
            if ror_instr.first_operand.strip().startswith('byte'):
                bits = 8

            elif ror_instr.first_operand.strip().startswith('word'):
                bits = 16

            elif ror_instr.first_operand.strip().startswith('dword'):
                bits = 32

            elif ror_instr.first_operand.strip().startswith('qword'):
                bits = 64

            else:
                bits = self.BITS

            new_value = self.rotate_right(current_value, immediate, bits)
            self.dereference_operand_store(ror_instr.first_operand, new_value)

    def run_ror(self, ror_instr):
        if ror_instr.second_operand.startswith('0x'):
            immediate = int(ror_instr.second_operand, 16)

        elif ror_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(ror_instr.second_operand)

        else:
            raise Exception('Unknown operand: {0}'.format(ror_instr.second_operand))

        if ror_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(ror_instr.first_operand)

        elif '[' in ror_instr.first_operand:
            current_value = self.dereference_operand_read(ror_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(ror_instr.first_operand))
    

        if ror_instr.first_operand in self.KNOWN_REGISTERS:
            new_value = self.rotate_right(current_value, immediate, self.get_register_size_bits(ror_instr.first_operand))
            register_size_bits = self.get_register_size_bits(ror_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if ror_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(ror_instr.first_operand, new_value)

        elif '[' in ror_instr.first_operand:
            if ror_instr.first_operand.strip().startswith('byte'):
                bits = 8

            elif ror_instr.first_operand.strip().startswith('word'):
                bits = 16

            elif ror_instr.first_operand.strip().startswith('dword'):
                bits = 32

            elif ror_instr.first_operand.strip().startswith('qword'):
                bits = 64

            else:
                bits = self.BITS

            new_value = self.rotate_right(current_value, immediate, bits)
            self.dereference_operand_store(ror_instr.first_operand, new_value)

    def rotate_right(self, number, rotations, bits):
        binary = format(number, '#0{0}b'.format(bits+2))[2:]

        for i in range(rotations % bits):
            binary = binary[-1] + binary[:-1]

        return int('0b{0}'.format(binary), 2)

    def rotate_left(self, number, rotations, bits):
        binary = format(number, '#0{0}b'.format(bits+2))[2:]

        for i in range(rotations % bits):
            binary = binary[1:] + binary[0]

        return int('0b{0}'.format(binary), 2)

    def run_sbb(self, sub_instr):
        # sbb is implemented exactly as sub, without dealing with the carry bit
        # perfect correctness is not the priority - the side effects are acceptable

        if sub_instr.second_operand.startswith('0x'):
            immediate = int(sub_instr.second_operand, 16)

        elif sub_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(sub_instr.second_operand)

        elif '[' in sub_instr.second_operand:
            immediate = self.dereference_operand_read(sub_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(sub_instr.second_operand))

        if sub_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(sub_instr.first_operand)

        elif '[' in sub_instr.first_operand:
            current_value = self.dereference_operand_read(sub_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(sub_instr.first_operand))
    
        new_value = current_value - immediate

        if sub_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(sub_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if sub_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(sub_instr.first_operand, new_value)

        elif '[' in sub_instr.first_operand:
            self.dereference_operand_store(sub_instr.first_operand, new_value)

    def run_lea(self, lea_instr):
        if lea_instr.first_operand not in self.KNOWN_REGISTERS:
            raise Exception('Unknown operand: {0}'.format(self.first_operand))
        
        i = lea_instr.second_operand.find('[')
        j = lea_instr.second_operand.find(']')

        if i == -1 or j == -1:
            raise Exception('Invalid operand: {0}'.format(lea_instr.second_operand))

        operand = lea_instr.second_operand[i+1:j]
        value = self.expand_operand_to_immediate(operand)
        self.set_register_value(lea_instr.first_operand, value)

    def run_lds(self, lds_instr):
        self.notify_segment_register_exception(SEGMENT_REGISTER_DS)

    def run_lss(self, lss_instr):
        self.notify_segment_register_exception(SEGMENT_REGISTER_SS)

    def run_les(self, les_instr):
        self.notify_segment_register_exception(SEGMENT_REGISTER_ES)

    def run_lfs(self, lfs_instr):
        self.notify_segment_register_exception(SEGMENT_REGISTER_FS)

    def run_lgs(self, lgs_instr):
        self.notify_segment_register_exception(SEGMENT_REGISTER_GS)

    def run_leave(self, leave_instr):
        if self.BITS == 64:
            stack_ptr = 'rsp'
            base_ptr = 'rbp'

        else:
            stack_ptr = 'esp'
            base_ptr = 'ebp'

        stack_ptr_value = self.get_register_value(stack_ptr)
        base_ptr_value = self.get_register_value(base_ptr)

        self.set_register_value(stack_ptr, base_ptr_value)
        self.exec_instruction(x86Instruction('pop {0}'.format(base_ptr)))

    def run_jmp(self, jmp_instr):
        self.notify_flow_deviation_exception(OPERATION_JMP)

    def run_call(self, call_instr):
        self.notify_flow_deviation_exception(OPERATION_CALL)

    def run_int(self, call_instr):
        self.notify_flow_deviation_exception(OPERATION_INTERRUPT)

    def run_syscall(self, call_instr):
        self.notify_flow_deviation_exception(OPERATION_SYSCALL)

    def run_dbgbreak(self, call_instr):
        self.notify_flow_deviation_exception(OPERATION_DBGBREAK)

    def run_xchg(self, xchg_instr):
        if xchg_instr.second_operand in self.KNOWN_REGISTERS:
            right_operand_value = self.get_register_value(xchg_instr.second_operand)

        elif '[' in xchg_instr.second_operand:
            right_operand_value = self.dereference_operand_read(xchg_instr.second_operand)

            if right_operand_value == None:
                # read exception occurred
                right_operand_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(xchg_instr.second_operand))

        if xchg_instr.first_operand in self.KNOWN_REGISTERS:
            left_operand_value = self.get_register_value(xchg_instr.first_operand)

        elif '[' in xchg_instr.first_operand:
            left_operand_value = self.dereference_operand_read(xchg_instr.first_operand)

            if left_operand_value == None:
                # read exception occurred
                left_operand_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(xchg_instr.first_operand))

        if xchg_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(xchg_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(right_operand_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(right_operand_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(right_operand_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(right_operand_value).value

            if xchg_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(xchg_instr.first_operand, new_value)

        elif '[' in xchg_instr.first_operand:
            self.dereference_operand_store(xchg_instr.first_operand, right_operand_value)

        if xchg_instr.second_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(xchg_instr.second_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(left_operand_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(left_operand_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(left_operand_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(left_operand_value).value

            if xchg_instr.second_operand in self.KNOWN_REGISTERS:
                self.set_register_value(xchg_instr.second_operand, new_value)

        elif '[' in xchg_instr.second_operand:
            self.dereference_operand_store(xchg_instr.second_operand, left_operand_value)


    def run_neg(self, neg_instr):
        if neg_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(neg_instr.first_operand)

        elif '[' in neg_instr.first_operand:
            current_value = self.dereference_operand_read(neg_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(neg_instr.first_operand))
    
        new_value = 0 - current_value

        if neg_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(neg_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if neg_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(neg_instr.first_operand, new_value)

        elif '[' in neg_instr.first_operand:
            self.dereference_operand_store(neg_instr.first_operand, new_value)

    def run_test(self, test_instr):
        if test_instr.second_operand.startswith('0x'):
            immediate = int(test_instr.second_operand, 16)

        elif test_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(test_instr.second_operand)

        elif '[' in test_instr.second_operand:
            immediate = self.dereference_operand_read(test_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(test_instr.second_operand))

        if test_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(test_instr.first_operand)

        elif '[' in test_instr.first_operand:
            current_value = self.dereference_operand_read(test_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(test_instr.first_operand))
    
        # after reading from both operands, do nothing
        # the operations above are performed only to trigger page faults (when it applies)

    def run_cmp(self, cmp_instr):
        if cmp_instr.second_operand.startswith('0x'):
            immediate = int(cmp_instr.second_operand, 16)

        elif cmp_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(cmp_instr.second_operand)

        elif '[' in cmp_instr.second_operand:
            immediate = self.dereference_operand_read(cmp_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(cmp_instr.second_operand))

        if cmp_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(cmp_instr.first_operand)

        elif '[' in cmp_instr.first_operand:
            current_value = self.dereference_operand_read(cmp_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(cmp_instr.first_operand))
    
        # after reading from both operands, do nothing
        # the operations above are performed only to trigger page faults (when it applies)

    def run_sete(self, sete_instr):
        if sete_instr.first_operand not in self.KNOWN_REGISTERS:
            raise Exception('Unknown operand: {0}'.format(sete_instr.first_operand))

        # do nothing - we don't want to effectivelly execute it

    def run_dec(self, dec_instr):
        immediate = 1

        if dec_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(dec_instr.first_operand)

        elif '[' in dec_instr.first_operand:
            current_value = self.dereference_operand_read(dec_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(dec_instr.first_operand))
    
        new_value = current_value - immediate

        if dec_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(dec_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if dec_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(dec_instr.first_operand, new_value)

        elif '[' in dec_instr.first_operand:
            self.dereference_operand_store(dec_instr.first_operand, new_value)

    def run_sub(self, sub_instr):
        if sub_instr.second_operand.startswith('0x'):
            immediate = int(sub_instr.second_operand, 16)

        elif sub_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(sub_instr.second_operand)

        elif '[' in sub_instr.second_operand:
            immediate = self.dereference_operand_read(sub_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(sub_instr.second_operand))

        if sub_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(sub_instr.first_operand)

        elif '[' in sub_instr.first_operand:
            current_value = self.dereference_operand_read(sub_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(sub_instr.first_operand))
    
        new_value = current_value - immediate

        if sub_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(sub_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if sub_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(sub_instr.first_operand, new_value)

        elif '[' in sub_instr.first_operand:
            self.dereference_operand_store(sub_instr.first_operand, new_value)
    

    def run_inc(self, inc_instr):
        immediate = 1

        if inc_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(inc_instr.first_operand)

        elif '[' in inc_instr.first_operand:
            current_value = self.dereference_operand_read(inc_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(inc_instr.first_operand))
    
        new_value = current_value + immediate

        if inc_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(inc_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if inc_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(inc_instr.first_operand, new_value)

        elif '[' in inc_instr.first_operand:
            self.dereference_operand_store(inc_instr.first_operand, new_value)

    def run_and(self, and_instr):
        if and_instr.second_operand.startswith('0x'):
            immediate = int(and_instr.second_operand, 16)

        elif and_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(and_instr.second_operand)

        elif '[' in and_instr.second_operand:
            immediate = self.dereference_operand_read(and_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(and_instr.second_operand))

        if and_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(and_instr.first_operand)

        elif '[' in and_instr.first_operand:
            current_value = self.dereference_operand_read(and_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(and_instr.first_operand))
    
        new_value = current_value & immediate

        if and_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(and_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if and_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(and_instr.first_operand, new_value)

        elif '[' in and_instr.first_operand:
            self.dereference_operand_store(and_instr.first_operand, new_value)


    def run_xor(self, xor_instr):
        if xor_instr.second_operand.startswith('0x'):
            immediate = int(xor_instr.second_operand, 16)

        elif xor_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(xor_instr.second_operand)

        elif '[' in xor_instr.second_operand:
            immediate = self.dereference_operand_read(xor_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(xor_instr.second_operand))

        if xor_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(xor_instr.first_operand)

        elif '[' in xor_instr.first_operand:
            current_value = self.dereference_operand_read(xor_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(xor_instr.first_operand))
    
        new_value = current_value ^ immediate

        if xor_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(xor_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if xor_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(xor_instr.first_operand, new_value)

        elif '[' in xor_instr.first_operand:
            self.dereference_operand_store(xor_instr.first_operand, new_value)

    def run_or(self, or_instr):
        if or_instr.second_operand.startswith('0x'):
            immediate = int(or_instr.second_operand, 16)

        elif or_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(or_instr.second_operand)

        elif '[' in or_instr.second_operand:
            immediate = self.dereference_operand_read(or_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(or_instr.second_operand))

        if or_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(or_instr.first_operand)

        elif '[' in or_instr.first_operand:
            current_value = self.dereference_operand_read(or_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(or_instr.first_operand))
    
        new_value = current_value | immediate

        if or_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(or_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if or_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(or_instr.first_operand, new_value)

        elif '[' in or_instr.first_operand:
            self.dereference_operand_store(or_instr.first_operand, new_value)

    def run_adc(self, add_instr):
        # adc is implemented exactly as add, without dealing with the carry bit
        # perfect correctness is not the priority - the side effects are acceptable
        if add_instr.second_operand.startswith('0x'):
            immediate = int(add_instr.second_operand, 16)

        elif add_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(add_instr.second_operand)

        elif '[' in add_instr.second_operand:
            immediate = self.dereference_operand_read(add_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(add_instr.second_operand))

        if add_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(add_instr.first_operand)

        elif '[' in add_instr.first_operand:
            current_value = self.dereference_operand_read(add_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(add_instr.first_operand))
    
        new_value = current_value + immediate

        if add_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(add_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if add_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(add_instr.first_operand, new_value)

        elif '[' in add_instr.first_operand:
            self.dereference_operand_store(add_instr.first_operand, new_value)


    def run_nop(self, nop_instr):
        # literally do nothing
        pass

    def run_endbr64(self, nop_instr):
        # do nothing - endbr64 is an instruction used in control flow
        pass

    def run_endbr32(self, nop_instr):
        # do nothing - endbr32 is an instruction used in control flow
        pass

    def run_vzeroupper(self, nop_instr):
        # do nothing - this instructions zeroes some parts of YMM and ZMM registers, but these are not useful for us
        # this instruction is probably not problematic (should not present bad side effects), so we can safely ignore it
        pass

    def run_push(self, push_instr):
        if push_instr.first_operand in self.KNOWN_REGISTERS:
            size_register = self.get_register_size_bits(push_instr.first_operand)

            if size_register not in [16, 32, 64]:
                raise Exception('Invalid register')

            if self.BITS == 64 and size_register == 32:
                raise Exception('Invalid register')

            write_size = int(size_register / 8)
            data = self.get_register_value(push_instr.first_operand)

            if write_size == 2:
                immediate = struct.pack('<H', data)

            elif write_size == 4:
                immediate = struct.pack('<I', data)

            elif write_size == 8:
                immediate = struct.pack('<Q', data)

        elif push_instr.first_operand.startswith('0x'):
            if self.BITS == 64:
                write_size = 8
                immediate = int(push_instr.first_operand, 16)
                immediate = struct.pack('<Q', immediate)

            else:
                write_size = 4
                immediate = int(push_instr.first_operand, 16)
                immediate = struct.pack('<I', immediate)

        elif '[' in push_instr.first_operand:
            immediate = self.dereference_operand_read(push_instr.first_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

            if push_instr.first_operand.startswith('word'):
                write_size = 2
                immediate = struct.pack('<H', immediate)

            elif push_instr.first_operand.startswith('dword'):
                write_size = 4
                immediate = struct.pack('<I', immediate)

            elif push_instr.first_operand.startswith('qword'):
                write_size = 8
                immediate = struct.pack('<Q', immediate)

            else:
                write_size = self.get_default_register_size_bytes()

                if write_size == 4:
                    immediate = struct.pack('<I', immediate)

                elif write_size == 8:
                    immediate = struct.pack('<Q', immediate)

        else:
            raise Exception('Unknown operand: {0}'.format(push_instr.first_operand))

        if self.BITS == 64:
            self.rsp -= write_size
            self.write_mem(self.rsp, immediate)

        else:
            self.esp -= write_size
            self.write_mem(self.esp, immediate)


    def run_retn(self, ret_instr):
        addition_to_esp = 4

        if self.BITS == 64:
            addition_to_esp = 8

        addition_to_esp += int(ret_instr.first_operand, 16)

        if self.BITS == 64:
            self.rsp += addition_to_esp

        else:
            self.esp += addition_to_esp

    def run_ret(self, ret_instr):
        # we don't care about eip for now, so just increment stack pointer

        if self.BITS == 64:
            self.rsp += 8

        else:
            self.esp += 4

    def run_movzx(self, mov_instr):
        if mov_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(mov_instr.second_operand)

        elif '[' in mov_instr.second_operand:
            immediate = self.dereference_operand_read(mov_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(mov_instr.second_operand))

        if mov_instr.first_operand not in self.KNOWN_REGISTERS:
            raise Exception('Unknown operand: {0}'.format(mov_instr.first_operand))
            
        self.set_register_value(mov_instr.first_operand, immediate)

    def run_movsxd(self, mov_instr):
        if mov_instr.first_operand not in self.KNOWN_REGISTERS:
            raise Exception('Unknown operand: {0}'.format(mov_instr.first_operand))

        if mov_instr.second_operand not in self.KNOWN_REGISTERS:
            raise Exception('Unknown operand: {0}'.format(mov_instr.second_operand))

        immediate = self.get_register_value(mov_instr.second_operand)
        src_bits = self.get_register_size_bits(mov_instr.second_operand)

        if src_bits == 8:
            immediate = ctypes.c_int8(immediate).value

        elif src_bits == 16:
            immediate = ctypes.c_int16(immediate).value

        elif src_bits == 32:
            immediate = ctypes.c_int32(immediate).value

        else:
            raise Exception('Unknown operand: {0}'.format(mov_instr.second_operand))

        dst_bits = self.get_register_size_bits(mov_instr.first_operand)

        if dst_bits == 8:
            immediate = ctypes.c_uint8(immediate).value

        elif dst_bits == 16:
            immediate = ctypes.c_uint16(immediate).value

        elif dst_bits == 32:
            immediate = ctypes.c_uint32(immediate).value

        elif dst_bits == 64:
            immediate = ctypes.c_uint64(immediate).value

        else:
            raise Exception('Unknown operand: {0}'.format(mov_instr.first_operand))

        self.set_register_value(mov_instr.first_operand, immediate)

    def run_bsf(self, mov_instr):
        if mov_instr.first_operand not in self.KNOWN_REGISTERS:
            raise Exception('Unknown operand: {0}'.format(mov_instr.first_operand))

        if mov_instr.second_operand not in self.KNOWN_REGISTERS:
            raise Exception('Unknown operand: {0}'.format(mov_instr.second_operand))

        immediate = self.get_register_value(mov_instr.second_operand)
        found_index = None
        for index in range(0, 64):
            if immediate & (1 << index) != 0:
                found_index = index
                break

        if found_index != None:
            self.set_register_value(mov_instr.first_operand, found_index)

    def run_mov(self, mov_instr):
        if mov_instr.second_operand.startswith('0x'):
            immediate = int(mov_instr.second_operand, 16)

        elif mov_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(mov_instr.second_operand)

        elif '[' in mov_instr.second_operand:
            immediate = self.dereference_operand_read(mov_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(mov_instr.second_operand))

        if mov_instr.first_operand in self.KNOWN_REGISTERS:
            self.set_register_value(mov_instr.first_operand, immediate)

        elif '[' in mov_instr.first_operand:
            self.dereference_operand_store(mov_instr.first_operand, immediate)

    def run_cmovne(self, mov_instr):
        # this instruction is a conditional move if not equals
        # it is more important to detect side effects than actually being precise in this instruction
        # so we just assume the move will occur and implement the move operation

        if mov_instr.second_operand.startswith('0x'):
            immediate = int(mov_instr.second_operand, 16)

        elif mov_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(mov_instr.second_operand)

        elif '[' in mov_instr.second_operand:
            immediate = self.dereference_operand_read(mov_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(mov_instr.second_operand))

        if mov_instr.first_operand in self.KNOWN_REGISTERS:
            self.set_register_value(mov_instr.first_operand, immediate)

        elif '[' in mov_instr.first_operand:
            self.dereference_operand_store(mov_instr.first_operand, immediate)

    def get_packed_invalid_read_data(self, read_size):
        if read_size == 8:
            return struct.pack('<Q', 0xdeadbeefdeadbeef)

        elif read_size == 4:
            return struct.pack('<I', 0xdeadbeef)

        elif read_size == 2:
            return struct.pack('<H', 0xdead)

        elif read_size == 1:
            return struct.pack('<B', 0xde)
        
        return struct.pack('<Q', 0xdeadbeef)            

    def run_pop(self, pop_instr):
        stack_pointer_value = self.get_stack_pointer_value()

        if pop_instr.first_operand in self.KNOWN_REGISTERS:
            size_register = self.get_register_size_bits(pop_instr.first_operand)

            if size_register not in [16, 32, 64]:
                raise Exception('Invalid target register')

            if self.BITS == 64 and size_register == 32:
                raise Exception('Invalid target register')

            read_size = int(size_register / 8)
            data = self.read_mem(stack_pointer_value, read_size)

            if data == None:
                data = self.get_packed_invalid_read_data(read_size)

            if read_size == 2:
                value = struct.unpack('<H', data)[0]

            elif read_size == 4:
                value = struct.unpack('<I', data)[0]

            elif read_size == 8:
                value = struct.unpack('<Q', data)[0]

            self.set_register_value(pop_instr.first_operand, value)

            if self.BITS == 64:
                self.rsp += read_size

            else:
                self.esp += read_size

        elif '[' in pop_instr.first_operand:
            if pop_instr.first_operand.startswith('word'):
                read_size = 2

            elif pop_instr.first_operand.startswith('dword'):
                read_size = 4

            elif pop_instr.first_operand.startswith('qword'):
                read_size = 8

            else:
                read_size = self.get_default_register_size_bytes()

            data = self.read_mem(stack_pointer_value, read_size)

            if data == None:
                data = self.get_packed_invalid_read_data(read_size)

            if read_size == 2:
                value = struct.unpack('<H', data)[0]

            elif read_size == 4:
                value = struct.unpack('<I', data)[0]

            elif read_size == 8:
                value = struct.unpack('<Q', data)[0]

            self.dereference_operand_store(pop_instr.first_operand, value)

            if self.BITS == 64:
                self.rsp += read_size
            
            else:
                self.esp += read_size            

    def run_add(self, add_instr):
        if add_instr.second_operand.startswith('0x'):
            immediate = int(add_instr.second_operand, 16)

        elif add_instr.second_operand in self.KNOWN_REGISTERS:
            immediate = self.get_register_value(add_instr.second_operand)

        elif '[' in add_instr.second_operand:
            immediate = self.dereference_operand_read(add_instr.second_operand)

            if immediate == None:
                # read exception occurred
                immediate = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(add_instr.second_operand))

        if add_instr.first_operand in self.KNOWN_REGISTERS:
            current_value = self.get_register_value(add_instr.first_operand)

        elif '[' in add_instr.first_operand:
            current_value = self.dereference_operand_read(add_instr.first_operand)

            if current_value == None:
                # read exception occurred
                current_value = INVALID_READ_DATA

        else:
            raise Exception('Unknown operand: {0}'.format(add_instr.first_operand))
    
        new_value = current_value + immediate

        if add_instr.first_operand in self.KNOWN_REGISTERS:
            register_size_bits = self.get_register_size_bits(add_instr.first_operand)

            if register_size_bits == 64:
                new_value = ctypes.c_uint64(new_value).value

            elif register_size_bits == 32:
                new_value = ctypes.c_uint32(new_value).value

            elif register_size_bits == 16:
                new_value = ctypes.c_uint16(new_value).value

            elif register_size_bits == 8:
                new_value = ctypes.c_uint8(new_value).value

            if add_instr.first_operand in self.KNOWN_REGISTERS:
                self.set_register_value(add_instr.first_operand, new_value)

        elif '[' in add_instr.first_operand:
            self.dereference_operand_store(add_instr.first_operand, new_value)
    
    def dereference_operand_store(self, operand, value):
        value = ctypes.c_uint64(value).value

        original_operand = operand
        i = operand.find('[')
        j = operand.find(']')

        if i == -1 or j == -1:
            raise Exception('Invalid operand: {0}'.format(operand))

        operand = operand[i+1:j]
        address = self.expand_operand_to_immediate(operand)

        if original_operand.startswith('byte'):
            value = value & 0x00000000000000ff
            self.write_mem(address, struct.pack('<B', value))

        elif original_operand.startswith('word'):
            value = value & 0x000000000000ffff
            self.write_mem(address, struct.pack('<H', value))

        elif original_operand.startswith('dword'):
            value = value & 0x00000000ffffffff
            self.write_mem(address, struct.pack('<I', value))

        elif original_operand.startswith('qword'):
            value = value
            self.write_mem(address, struct.pack('<Q', value))

        else:
            default_register_size = self.get_default_register_size_bytes()

            if default_register_size == 4:
                value = value & 0x00000000ffffffff
                self.write_mem(address, struct.pack('<I', value))

            elif default_register_size == 8:
                value = value
                self.write_mem(address, struct.pack('<Q', value))

    def dereference_operand_read(self, operand):
        original_operand = operand
        i = operand.find('[')
        j = operand.find(']')

        if i == -1 or j == -1:
            raise Exception('Invalid operand: {0}'.format(operand))

        operand = operand[i+1:j]
        address = self.expand_operand_to_immediate(operand)

        if original_operand.startswith('byte'):
            data = self.read_mem(address, 1)
            if data == None:
                return data

            data = struct.unpack('<B', data)[0]

        elif original_operand.startswith('word'):
            data = self.read_mem(address, 2)
            if data == None:
                return data

            data = struct.unpack('<H', data)[0]

        elif original_operand.startswith('dword'):
            data = self.read_mem(address, 4)
            if data == None:
                return data

            data = struct.unpack('<I', data)[0]

        elif original_operand.startswith('qword'):
            data = self.read_mem(address, 8)
            if data == None:
                return data

            data = struct.unpack('<Q', data)[0]

        else:
            default_register_size = self.get_default_register_size_bytes()
            data = self.read_mem(address, default_register_size)
            if data == None:
                return data

            if default_register_size == 4:
                data = struct.unpack('<I', data)[0]

            elif default_register_size == 8:
                data = struct.unpack('<Q', data)[0]

        return data

    def safe_eval_math(self, math_expression):
        allowed_chars = '0123456789+-*'
        for c in math_expression:
            if c not in allowed_chars:
                raise Exception('Unsafe eval: {0}'.format(math_expression))

        return eval(math_expression)

    def expand_operand_to_immediate(self, operand):
        tmp = operand.replace('+', ' ').replace('-', ' ').replace('*', ' ').split(' ')
        math_operations = []

        for letter in operand:
            if letter in '+-*':
                math_operations.append(letter)

        new_operand = ''

        for item in tmp:
            if item in self.KNOWN_REGISTERS:
                value = self.get_register_value(item)
                new_operand += str(value)

                if len(math_operations) > 0:
                    new_operand += math_operations.pop(0)

            else:
                if item.startswith('0x'):
                    item = str(int(item, 16))

                new_operand += item

                if len(math_operations) > 0:
                    new_operand += math_operations.pop(0)

        return self.safe_eval_math(new_operand)

    def get_register_size_bits(self, register_name):
        if register_name in ['rsp', 'rbp', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
            return 64

        elif register_name in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']:
            return 32

        elif register_name in ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'sp', 'bp', 'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']:
            return 16

        elif register_name in ['ah', 'al', 'bh', 'bl','ch', 'cl', 'dh', 'dl', 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']:
            return 8

        else:
            raise Exception('Unknown register: {0}'.format(register_name))

    def get_effective_register_name(self, name):
        if name in ['rax', 'eax', 'ax', 'ah', 'al']:
            if self.BITS == 64:
                return 'rax'

            else:
                return 'eax'

        elif name in ['rbx', 'ebx', 'bx', 'bh', 'bl']:
            if self.BITS == 64:
                return 'rbx'

            else:
                return 'ebx'

        elif name in ['rcx', 'ecx', 'cx', 'ch', 'cl']:
            if self.BITS == 64:
                return 'rcx'

            else:
                return 'ecx'

        elif name in ['rdx', 'edx', 'dx', 'dh', 'dl']:
            if self.BITS == 64:
                return 'rdx'

            else:
                return 'edx'

        elif name in ['rdi', 'edi', 'di']:
            if self.BITS == 64:
                return 'rdi'

            else:
                return 'edi'

        elif name in ['rsi', 'esi', 'si']:
            if self.BITS == 64:
                return 'rsi'

            else:
                return 'esi'

        elif name in ['rsp', 'esp', 'sp']:
            if self.BITS == 64:
                return 'rsp'

            else:
                return 'esp'

        elif name in ['rbp', 'ebp', 'bp']:
            if self.BITS == 64:
                return 'rbp'

            else:
                return 'ebp'

        elif name in ['r8', 'r8d', 'r8w', 'r8b']:
            return 'r8'

        elif name in ['r9', 'r9d', 'r9w', 'r9b']:
            return 'r9'

        elif name in ['r10', 'r10d', 'r10w', 'r10b']:
            return 'r10'

        elif name in ['r11', 'r11d', 'r11w', 'r11b']:
            return 'r11'

        elif name in ['r12', 'r12d', 'r12w', 'r12b']:
            return 'r12'

        elif name in ['r13', 'r13d', 'r13w', 'r13b']:
            return 'r13'

        elif name in ['r14', 'r14d', 'r14w', 'r14b']:
            return 'r14'

        elif name in ['r15', 'r15d', 'r15w', 'r15b']:
            return 'r15'

        else:
            raise Exception('Unknown register: {0}'.format(register_name))

    def get_stack_pointer_value(self):
        if self.BITS == 64:
            return self.get_register_value('rsp')

        return self.get_register_value('esp')

    def get_register_value(self, register_name):
        if register_name in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
            return getattr(self, register_name) & 0xffffffffffffffff

        if register_name in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']:
            return getattr(self, self.get_effective_register_name(register_name)) & 0xffffffff

        elif register_name in ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'sp', 'bp', 'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']:
            return getattr(self, self.get_effective_register_name(register_name)) & 0x0000ffff

        elif register_name in ['ah', 'bh', 'ch', 'dh']:
            return getattr(self, self.get_effective_register_name(register_name)) & 0x0000ff00

        elif register_name in ['al', 'bl', 'cl', 'dl', 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']:
            return getattr(self, self.get_effective_register_name(register_name)) & 0x000000ff

        else:
            raise Exception('Unknown register: {0}'.format(register_name))

    def set_register_value(self, register_name, value):
        if register_name in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
            new_value = value & 0xffffffffffffffff
            return setattr(self, register_name, new_value)

        elif register_name in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']:
            new_value = value & 0x00000000ffffffff
            return setattr(self, self.get_effective_register_name(register_name), value)

        elif register_name in ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']:
            current_value = self.get_register_value(self.get_effective_register_name(register_name))
            new_value = (current_value & 0xffffffffffff0000) | value
            return setattr(self, self.get_effective_register_name(register_name), new_value)

        elif register_name in ['ah', 'bh', 'ch', 'dh']:
            current_value = self.get_register_value(self.get_effective_register_name(register_name))
            new_value = (current_value & 0xffffffffffff00ff) | (value << 8)
            return setattr(self, self.get_effective_register_name(register_name), new_value)

        elif register_name in ['al', 'bl', 'cl', 'dl', 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']:
            current_value = self.get_register_value(self.get_effective_register_name(register_name))
            new_value = (current_value & 0xffffffffffffff00) | value
            return setattr(self, self.get_effective_register_name(register_name), new_value)

        else:
            raise Exception('Unknown register: {0}'.format(register_name))

    def set_registers_default_initial_state(self):
        if self.BITS == 64:
            self.rax = 0x1011121314151617
            self.rbx = 0x2021222324252627
            self.rcx = 0x3031323334353637
            self.rdx = 0x4041424344454647
            self.rsi = 0x5051525354555657
            self.rdi = 0x6061626364656667
            self.r8 = 0x7071727374757677
            self.r9 = 0x8081828384858687
            self.r10 = 0x9091929394959697
            self.r11 = 0xa0a1a2a3a4a5a6a7
            self.r12 = 0xb0b1b2b3b4b5b6b7
            self.r13 = 0xc0c1c2c3c4c5c6c7
            self.r14 = 0xd0d1d2d3d4d5d6d7
            self.r15 = 0xe0e1e2e3e4e5e6e7
            self.rbp = self.DEFAULT_STACK_PTR
            self.rsp = self.rbp - 0x100

        else:
            self.eax = 0x10111213
            self.ebx = 0x20212223
            self.ecx = 0x30313233
            self.edx = 0x40414243
            self.esi = 0x50515253
            self.edi = 0x60616263
            self.ebp = self.DEFAULT_STACK_PTR
            self.esp = self.ebp - 0x100
