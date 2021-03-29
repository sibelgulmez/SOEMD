import os


def writeFeatureAsSequence(filename, extension, sequence, sep=',',outfile=''):
    if(outfile==''):
        dirname         = os.path.dirname(filename)
    else:
        dirname         = outfile

    filename        = os.path.basename(filename)
    (filename, ext) = os.path.splitext(filename)
    output_filename = dirname+os.sep+extension+os.sep+filename+'.'+extension
    seq = ""
    os.makedirs(os.path.dirname(output_filename), exist_ok=True)
    with open(output_filename, 'w') as output_file:
        for s in sequence:
            seq = seq+str(s)+sep
        output_file.write(seq)


def writeIntoFile(filename, extension, content):
    dirname         = os.path.dirname(filename)


    filename        = os.path.basename(filename)
    (filename, ext) = os.path.splitext(filename)
    output_filename = dirname+os.sep+extension+os.sep+filename+'.'+extension

    os.makedirs(os.path.dirname(output_filename), exist_ok=True)
    with open(output_filename, 'w') as output_file:
        output_file.write(content)
