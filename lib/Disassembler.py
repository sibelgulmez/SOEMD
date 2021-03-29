import distorm3


def diassemble(filename, bits='32bit'):
    with open(filename,'rb') as input_file:
        code = input_file.read()
    offset = 0

    if bits == '16bit':
        mode = distorm3.Decode16Bits
    elif bits == '32bit':
        mode = distorm3.Decode32Bits
    else:
        mode = distorm3.Decode64Bit
    iterable = distorm3.DecodeGenerator(offset, code, mode)

    return iterable
