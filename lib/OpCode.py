import Disassembler

def getOpcode(filename, delimeter='\n', bits='32bit'):

    iterable = Disassembler.diassemble(filename,bits)

    opcode_code = ''
    for (offset, size, instruction, hexdump) in iterable:
        # To avoid TypeError: a bytes-like object is required, not 'str'
        instruction = instruction.decode()

        opcode = instruction.split(" ")[0]  # get opcode
        opcode_code += opcode+delimeter

    return opcode_code

def getOpcodeFromFile(filename,delimiter=","):
    with open(filename,"r") as file:
        opcodes = file.read()
    opcodes=opcodes[:len(opcodes)-1]
    return opcodes.split(delimiter)
