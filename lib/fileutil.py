import os

def getFilePaths(directory, extensionList=[], reverse=False):
    """
    
    :param directory: source directory
    :param extensionList: 
    :param reverse: list of extensions (to include in the output) 
    :return: list of the files in that directory and its subdirectories (as file paths, not as file names)
    """
    file_paths = []
    for root, directories, files in os.walk(directory):
        for filename in files:
            if (len(extensionList) > 0):
                extension = os.path.splitext(filename)[1]
                if ((extension.lower() in extensionList) or (extension.upper() in extensionList)):
                    if (not reverse):
                        filepath = os.path.join(root, filename)
                        file_paths.append(filepath)
                elif (reverse):
                    filepath = os.path.join(root, filename)
                    file_paths.append(filepath)
            else:
                filepath = os.path.join(root, filename)
                file_paths.append(filepath)
    # print("Number of file found : " + str(len(file_paths)))
    return file_paths


def writeFeatureAsSequence(filename, extension, sequence, sep=',',outfile=''):
    """

    :param filename: path of the input file
    :param extension: desired extension of the output file (without dot)
    :param sequence: sequence to process
    :param sep: seperator of the sequence
    :param outfile: functional directory of the output file. if not given, the output file will be saved into the directory of the input file.
    :return: none
    """

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
    """
        :param filename: path of the output file
        :param extension: extension of the output file
        :param content: content to write into the file
        :return: none
    """
    dirname         = os.path.dirname(filename)
    filename        = os.path.basename(filename)
    (filename, ext) = os.path.splitext(filename)
    output_filename = dirname+os.sep+extension+os.sep+filename+'.'+extension
    os.makedirs(os.path.dirname(output_filename), exist_ok=True)
    with open(output_filename, 'w') as output_file:
        output_file.write(content)

