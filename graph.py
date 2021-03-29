import os, errno, copy
from lib import OpCode, fileutil

def create_dict(filelist, dictfile='.'):
    if os.path.isfile(dictfile):
        print('Dict fetching')
        return read_dict_file(dictfile)
    else:
        oset = set()
        index=1
        for file in filelist:
            opcode_seq = OpCode.getOpcodeFromFile(file)
            if ("" in opcode_seq):
                opcode_seq.remove("")
            oset.update(set(opcode_seq))
            print('Creating the Dictionary - Reading Opcode File ' + str(index) + '/' + str(len(filelist)) + ' - Current Size of Dict: ' + str(len(list(oset))))
            index+=1
        dict_op = op_num_mapping(oset)
        write_dict(dictfile, dict_op)
        return dict_op

def op_num_mapping(opcodeset):
    dict_op= dict()
    i = 1
    for o in opcodeset:
        dict_op[o] = i  # creating dictionary of opcode to num
        i += 1
    return dict_op

def write_dict(filename,data):
    if (os.path.isfile(filename)):
        return
    try:
        os.makedirs(os.path.dirname(filename))
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(os.path.dirname(filename)):
            pass
        else: raise

    with open(filename, 'w') as df:
        for i in data.keys():
            s = str(data[i])+" "+str(i)
            df.write(s)
            df.write(os.linesep)

def read_dict_file(dictfile):
    f = open(dictfile,'r')
    content = f.readlines()
    f.close()
    rows=[]
    for c in content:
        rows.append(c[:len(c)-1])
    dict_op = dict()
    for r in rows:
        splitted = r.split()
        dict_op[splitted[1]] = splitted[0]
    return dict_op

def op_to_num_write (filelist, dict_op):
    i=0
    for file in filelist:
        print(file)
        opcode_seq = OpCode.getOpcodeFromFile(filename=file)
        if ("" in opcode_seq):
            opcode_seq.remove("")
        optonum_file = file.replace('/opcode/','/graph/OpToNum/').replace('.opcode', '.optonum')
        freq = {}

        last_opcode = opcode_seq[0]
        num_seq = str(dict_op[last_opcode]) + ","
        for index in range(1,len(opcode_seq)):
            opcode = opcode_seq[index]
            if opcode not in dict_op.keys():
                dict_op[opcode] = str(len(list(dict_op)))
            num_seq += str(dict_op[opcode]) + ","
            cell = str(dict_op[last_opcode]) + "->" + str(dict_op[opcode])
            if (cell in freq.keys()):
                freq[str(cell)] += 1
            else:
                freq[str(cell)] = 1
            last_opcode = opcode
        if (os.path.isfile(optonum_file)):
            print(str(i) + '/' + str(len(filelist)) +' Graph files has been written already')
        else:
            try:
                os.makedirs(os.path.dirname(optonum_file))
            except OSError as exc:
                if exc.errno == errno.EEXIST and os.path.isdir(os.path.dirname(optonum_file)):
                    pass
                else: raise
            f = open(optonum_file, 'w')
            f.write(num_seq)
            f.close()
            print(str(i) + '/' + str(len(filelist)) +' .optonum file has been written' )
            EdgeListGraphDataset(file, opcode_seq, dict_op, freq)
            print(str(i) + '/' + str(len(filelist)) +' .dict file has been written')
            print(str(i) + '/' + str(len(filelist)) +' .edge file has been written')
        i+=1
    return

def EdgeListGraphDataset(file, opcode_seq, dict_op, freq):
    temp_dict = copy.deepcopy(dict_op)
    dictfile = file.replace('/opcode/','/graph/dict/').replace('.opcode', '.dict')
    file_dict_op = local_enum_dict_dataset(file,dictfile, temp_dict)
    edge_set = set()
    for index in range(len(opcode_seq) - 1):
        num = int(file_dict_op[opcode_seq[index]])
        suffix_num = int(file_dict_op[opcode_seq[index+1]])
        edge_set.add((num,suffix_num))
    edge_list= list(edge_set)
    edge_list.sort(key=lambda tup:tup[0],reverse=False)
    edge_list_write(file,edge_list, freq)
    return

def local_enum_dict_dataset(filename,dictfile, all_dict_op):
    if (os.path.isfile(dictfile)):
        return get_dict_dataset(dictfile)
    else:
        oset = set()
        ops = OpCode.getOpcodeFromFile(filename)
        oset.update(set(ops))

        temp_dict = all_dict_op
        for i in list(temp_dict):
            if (i not in oset):
                del all_dict_op[i]

        write_dict(dictfile, all_dict_op)
        return all_dict_op

def get_dict_dataset(dictfile):
    dict_op = dict()
    with open(dictfile, 'r') as df:
        for line in df:
            if(line!=''):              
                d = line.split()
                dict_op[d[1]]=d[0]
    return dict_op

def edge_list_write(filepath, edge_list, freq):
    edgefile = filepath.replace('/opcode/', '/graph/edge/').replace('.opcode', '.edge')
    if (os.path.isfile(edgefile)):
        return
    try:
        os.makedirs(os.path.dirname(edgefile))
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(os.path.dirname(edgefile)):
            pass
        else:
            raise

    f = open(edgefile, 'w')
    for edge in edge_list:
        cell = str(edge[0]) + '->' + str(edge[1])
        f.write(cell + ' ' + str(freq[str(cell)]) + '\n')
    f.close()
    return

def mk_dir(directory):
    pathg = directory + "/graph"
    try:
        os.mkdir(pathg)
    except OSError:
        print("Creation of the directory %s failed" % pathg)
    else:
        print("Successfully created the directory %s " % pathg)

    pathe = pathg+"/edge"
    try:
        os.mkdir(pathe)
    except OSError:
        print("Creation of the directory %s failed" % pathe)
    else:
        print("Successfully created the directory %s " % pathe)


    patho = pathg+"/optonum"
    try:
        os.mkdir(patho)
    except OSError:
        print("Creation of the directory %s failed" % patho)
    else:
        print("Successfully created the directory %s " % patho)



    pathd = pathg+"/edge"
    try:
        os.mkdir(pathd)
    except OSError:
        print("Creation of the directory %s failed" % pathd)
    else:
        print("Successfully created the directory %s " % pathd)
    return

if __name__ == "__main__":
    directory = ""
    listOfFile = fileutil.getFilePaths(directory, [".opcode"])
    dict_op = create_dict(listOfFile, directory + "/graph/opcode_dict.txt")
    op_to_num_write(listOfFile,dict_op)
