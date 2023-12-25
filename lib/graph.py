from lib import fileutil, disassembler
import os

def generateEdgeFiles(dataset_directory):
    """
    Generate graphs and save "edge" files. An edge file contains the edges and their weights (frequency)
    :param dataset_directory:  directory of the dataset
    :return: none
    """
    edge_directory = dataset_directory + "/edge"
    if not os.path.isdir(edge_directory): # generate a directory to save edge files
       os.makedirs(edge_directory)
    opcodepaths = fileutil.getFilePaths(dataset_directory + "/opcode", extensionList=[".opcode"]) # get the list of opcode files
    print("Creating edge files in the directory:", dataset_directory)
    for opcodepath in opcodepaths:
        edgepath = opcodepath.replace("opcode", "edge")
        if os.path.isfile(edgepath): # if already created, continue
            continue
        disassembler_object = disassembler.opcode()
        disassembler_object.readOpcodeFromFile(opcodepath)
        opcodes = disassembler_object.opcode_sequence_as_list
        edges_dict = dict()
        # generate edge frequencies
        for i in range(len(opcodes)-1):
            edge = opcodes[i] + "->" + opcodes[i + 1]
            if edge in edges_dict.keys():
                edges_dict[edge] += 1
            else:
                edges_dict[edge] = 1
        # sort them and write into the file
        sorted_dict = dict(sorted(edges_dict.items()))
        f = open(edgepath, "w")
        for edge in sorted_dict.keys():
            toWrite = edge + " " + str(sorted_dict[edge]) + "\n"
            f.write(toWrite)
        f.close()


