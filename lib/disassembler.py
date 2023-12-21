import os

import distorm3
from lib import fileutil
"""
    Disassemble class
"""
class opcode():
    """
        :param source_file: path of the executable file
    """
    def __init__(self, source_file="."):
        self.source_file = source_file
        self.opcode_sequence_as_list = None
        self.opcode_sequence_as_str = None

    def disassemble(self):
        with open(self.source_file,'rb') as input_file:
            code = input_file.read()
        offset = 0
        mode = distorm3.Decode32Bits
        iterable = distorm3.DecodeGenerator(offset, code, mode)
        return iterable

    """
        Extracts opcodes of the source file
    """
    def extractOpcodes(self, delimeter=',', bits='32bit'):
        iterable = self.disassemble()

        opcode_code = ''
        for (offset, size, instruction, hexdump) in iterable:
            # To avoid TypeError: a bytes-like object is required, not 'str'
            try:
                instruction = instruction.decode() # get instruction
            except:
                instruction = instruction
            opcode = instruction.split(" ")[0]  # get opcode
            opcode_code += opcode+delimeter
        opcode_code = opcode_code[:-1] # deleting the last unnecessary delimeter
        self.opcode_sequence_as_list = opcode_code.split(delimeter)
        self.opcode_sequence_as_str = opcode_code


    """
        Reads opcodes from a previously saved file 
    """
    def readOpcodeFromFile(self, opcode_file_path, delimiter=","):
        with open(opcode_file_path,"r") as file:
            opcodes = file.read()
        opcodes=opcodes[:len(opcodes)-1]
        self.opcode_sequence_as_list = opcodes.split(delimiter)
        self.opcode_sequence_as_str = opcodes


    """     
        Saves the opcodes in a file.
    """
    def saveOpcodeFile(self, opcode_file_path):
        self.extractOpcodes()
        f = open(opcode_file_path,"w")
        f.write(self.opcode_sequence_as_str)
        f.close()


"""
    Creates opcode files for multiple executables and returns the paths of the created opcode files
    The directory hierarchy:
    ---DatasetName
    -------exe        -> this folder contains executable files
    -------opcode     -> this folder (will) contain opcode files
    -------edge       -> this folder (will) contain edge files
"""
def createOpcodeFiles(dataset_directory):
    print("Creating opcode files in the directory:", dataset_directory)
    opcode_directory = dataset_directory + "/opcode"
    if not os.path.isdir(opcode_directory):
        os.makedirs(opcode_directory)
    exe_file_list = fileutil.getFilePaths(dataset_directory, extensionList=[".exe", ".bin"])
    opcode_file_list = []
    for exe_file in exe_file_list:
        opcode_file = opcode(exe_file)
        opcode_file.extractOpcodes()
        opcode_file_path = exe_file.replace("exe", "opcode").replace(".bin", ".opcode")
        opcode_file.saveOpcodeFile(opcode_file_path)
        opcode_file_list.append(opcode_file_path)
    return opcode_file_list
