from lib import fileutil, w2v
import csv, random
import numpy as np

def getNodes(listOffile, count):
    malwares = []
    benigns = []

    flag = 0
    for i in range(len(listOffile)):
        filename = listOffile[i]
        if (flag == 0):
            malwares.append(filename)
            flag = 1
        else:
            benigns.append(filename)
            flag = 0

    malware_list = {}
    opcode_list = []
    import numpy as np
    freqs = np.zeros((len(listOffile)))
    for dictfile in malwares:
        f = open(dictfile, 'r')
        opcodes = f.readlines()
        f.close()
        for opcode in opcodes:
            opc = opcode.split()[0]
            if (opc in malware_list.keys()):
                malware_list[str(opc)] += 1
                freqs[opcode_list.index(str(opc))] += 1
            else:
                opcode_list.append(str(opc))
                freqs[(len(opcode_list) - 1)] = 1
                malware_list[str(opc)] = 1

    mw = []
    zipped = zip(opcode_list, freqs)
    zipped = sorted(zipped, key=lambda x: x[1])
    print('malwares:')
    opcode_list_sorted, freqs_sorted = zip(*zipped)
    for i in range(1, count+1):
        mw.append(opcode_list_sorted[len(opcode_list_sorted) - i])
        print("Opcode Index: " + str(opcode_list_sorted[len(opcode_list_sorted) - i]) + " Count:" + str((freqs_sorted[len(opcode_list_sorted) - i])))

    benign_list = {}
    opcode_list = []
    import numpy as np
    freqs = np.zeros((len(listOffile)))
    for dictfile in benigns:
        f = open(dictfile, 'r')
        opcodes = f.readlines()
        f.close()
        for opcode in opcodes:
            opc = opcode.split()[0]
            if (opc in benign_list.keys()):
                benign_list[str(opc)] += 1
                freqs[opcode_list.index(str(opc))] += 1
            else:
                opcode_list.append(str(opc))
                freqs[(len(opcode_list) - 1)] = 1
                benign_list[str(opc)] = 1
    bn = []
    zipped = zip(opcode_list, freqs)
    zipped = sorted(zipped, key=lambda x: x[1])
    print('benigns:')
    opcode_list_sorted, freqs_sorted = zip(*zipped)
    for i in range(1, count+1):
        bn.append(opcode_list_sorted[len(opcode_list_sorted) - i])
        print("Opcode Index: " + str(opcode_list_sorted[len(opcode_list_sorted) - i]) + " Count:" + str((freqs_sorted[len(opcode_list_sorted) - i])))
    return bn, mw

def del_edges(edge_nodes_from, edge_nodes_to, freqs, ratio):
    nodes = list(set(edge_nodes_from))
    for node in nodes:
        if (node in edge_nodes_from):
            first_index = edge_nodes_from.index(node)
            last_index = len(edge_nodes_from) - edge_nodes_from[-1::-1].index(node)
            sum = 0
            for freq in freqs[first_index:last_index]:
                sum += int(freq)
            Percent = (sum * ratio) / 100
            index = first_index
            for o in range(last_index - first_index):
                if (int(freqs[index]) < Percent):
                    del freqs[int(index)]
                    del edge_nodes_from[int(index)]
                    del edge_nodes_to[int(index)]
                else:
                    index += 1
    return edge_nodes_from, edge_nodes_to, freqs

def get_seq(seq_len, last_used_opcode, edge_nodes_from, edge_nodes_to, node_flag):
    seq=[]
    for j in range(seq_len - 1):
        first_index = edge_nodes_from.index(last_used_opcode)
        last_index = len(edge_nodes_from) - edge_nodes_from[-1::-1].index(last_used_opcode) - 1

        randomnumber = random.randint(first_index, last_index)
        next_opcode = edge_nodes_to[randomnumber]
        randomnumbers = []
        randomnumbers.append(randomnumber)
        while (j != seq_len - 2 and next_opcode not in edge_nodes_from and next_opcode):
            if (len(randomnumbers) == (last_index - first_index + 1)):
                node_flag = 1
                break
            while (randomnumber not in randomnumbers):
                randomnumber = random.randint(first_index, last_index)
            randomnumbers.append(randomnumber)
            next_opcode = edge_nodes_to[randomnumber]
        if (node_flag == 1):
            break
        last_used_opcode = next_opcode
        seq.append(last_used_opcode)
        return seq

def write_into_csv(w2Dim, seq_len, length, data, labels, seq_per_opcode, csvpath):
    csv_content = []
    header = []
    for i in range(w2Dim*seq_len*length):
        header.append("Vector" + str(i))
    header.append("class_id")
    csv_content.append(header)
    print(data.shape)
    walkPerFile = seq_per_opcode*length
    for i in range(int(len(labels) / walkPerFile)):
        single_item = []
        for j in range(walkPerFile):
            for k in range(seq_len):
                for l in range(w2Dim):
                    single_item.append(data[i * walkPerFile + j][k][l])
        if (labels[i * walkPerFile] == 1):
            single_item.append("malware")
        else:
            single_item.append("benign")
        csv_content.append(single_item)
    print('creating csv file')
    f = open(csvpath, "w")
    writer = csv.writer(f)
    writer.writerows(csv_content)
    f.close()
    print("CSV VECTOR FILE HAS BEEN WRITTEN")
    return

def soemd(graph_directory, seq_len, seq_per_opcode, mw_list, bn_list, ratio):

    listOffile = fileutil.getFilePaths(graph_directory, [".edge"])
    ds_size = len(listOffile)
    datalines = []
    labels = []
    exelabels = []
    flag = 1
    for i in range(ds_size):
        opcode_index = 1
        countOfWalks=0
        for p in range(len(mw_list)):
            if (flag == 1):  # malware
                opcode = str(mw_list[p])
            else:
                opcode = str(bn_list[p])

            filename=listOffile[i]
            f = open(filename, 'r')
            edge_lines = f.readlines()
            f.close()

            edge_nodes_from = []
            edge_nodes_to = []
            freqs = []
            for j in edge_lines:
                edge = j.split()[0]
                freqs.append(str(j.split()[1]))
                edge_nodes_from.append(edge.split('->')[0])
                edge_nodes_to.append(edge.split('->')[1])
            edge_nodes_from, edge_nodes_to, freqs = del_edges(edge_nodes_from, edge_nodes_to, freqs, ratio)

            for k in range(seq_per_opcode):
                if (opcode not in edge_nodes_from):
                    print("starting node not in the list")
                    break
                last_used_opcode = opcode
                if(last_used_opcode not in edge_nodes_from):
                    continue
                node_flag = 0
                seq = get_seq(seq_len, last_used_opcode, edge_nodes_from, edge_nodes_to, node_flag)
                seq.append(last_used_opcode)
                
                if (len(seq) == seq_len):
                    countOfWalks += 1
                    datalines.append(seq)
                    labels.append(flag)
                    exelabels.append(i)
                    print("File " + str(i) + " / " + str(ds_size-1) + ' - common opcode ' + str(
                opcode_index) + '/' + str(len(mw_list)) + ' - seq per opcode ' + str(k + 1) + '/' + str(seq_per_opcode) + ' total sample: ' + str(len(datalines)))
            opcode_index += 1
        if (countOfWalks != 0 and countOfWalks < len(mw_list)*seq_per_opcode):
            for k in range(countOfWalks):
                ind = countOfWalks - k -1
                del(datalines[ind])
                del(labels[ind])
                del(exelabels[ind])
        if (flag == 1):
            flag = 0
        else:
            flag = 1
    labels = np.array(labels)

    print('w2v started')
    w2Dim=4
    data = w2v.getvectorsVX(datalines, seq_len, w2Dim)
    print("w2v vectors had been obtained")
    write_into_csv(w2Dim, seq_len, len(mw_list), data, labels, seq_per_opcode, graph_directory + "/Vectors.csv")
    return

if __name__ == "__main__":
    graph_directory = ""
    nodeCount = 15
    edgeratio = 4 
    bn, mw = getNodes(fileutil.getFilePaths(graph_directory, [".dict"]), nodeCount)
    soemd(graph_directory, seq_len=50, seq_per_opcode=1, mw_list=mw, bn_list=bn, ratio=edgeratio)
