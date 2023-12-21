from lib import disassembler, graph, w2v
import csv, random, numpy, os

class file:
    def __init__(self, opcode_file_path, edge_file_path):
        self.opcode_file_path = opcode_file_path
        self.file_hash = os.path.splitext(os.path.basename(opcode_file_path))[0]
        self.edge_file_path = edge_file_path
        self.disassembler_object = disassembler.opcode(opcode_file_path)
        self.disassembler_object.readOpcodeFromFile(opcode_file_path)
        self.opcodes_as_str = self.disassembler_object.opcode_sequence_as_str
        self.opcodes_as_list = self.disassembler_object.opcode_sequence_as_list
        self.edge_dict = dict()
        self.gerenateEdgeDict()
    """
        Updates the frequency_dict with the new file whose opcode file path is given with opcode_file_path.
    """
    def calculateFrequencies(self, frequency_dict):
        for opcode in self.opcodes_as_list:
            if opcode in frequency_dict.keys():
                frequency_dict[opcode] +=1
            else:
                frequency_dict[opcode] = 1
        return frequency_dict

    """
        Reads the edge file and generates edge dictionary. 
    """
    def gerenateEdgeDict(self):
        f = open(self.edge_file_path, "r")
        content = f.readlines()
        f.close()
        if content[-1] == "": # if the last line is empty, delete it
            content = content [:-1]
        for c in content:
            edge, frequency = c.split(" ")
            edge_source, edge_destination = edge.split("->")
            if edge_source in self.edge_dict.keys():
                self.edge_dict[edge_source][edge_destination] = int(frequency)
            else:
                self.edge_dict[edge_source] = dict()
                self.edge_dict[edge_source][edge_destination] = int(frequency)

class dataset:
    """
        :param malware_opcodeFile_list: list, paths of the opcode files of the malware executables
        :param benign_opcodeFile_list: list, paths of the opcode files of the benign executables
        :param node_count:  number of nodes to extract, default = 15
        :param edge_ratio:  default = 4
    """
    def __init__(self, malware_opcodeFile_list = [], benign_opcodeFile_list = [], node_count = 15, edge_ratio = 4):
        self.node_count = node_count
        self.edge_ratio = edge_ratio
        self.malware_opcodeFile_list = malware_opcodeFile_list
        self.benign_opcodeFile_list = benign_opcodeFile_list
        self.malware_nodes = []
        self.benign_nodes = []
        self.number_of_malware_files = len(malware_opcodeFile_list)
        self.number_of_benign_files = len(benign_opcodeFile_list)
        self.total_number_of_files = len(benign_opcodeFile_list) + len(malware_opcodeFile_list)
        self.malware_files = []
        self.benign_files = []
        self.files = []
        self.generateFileObjects()
        self.extractNodes()
        self.removeEdges()


    """
        Generates an edge dictionary for each file and fill them into malware_files and benign_files
    """
    def generateFileObjects(self):
        for malware_opcodeFile_path in self.malware_opcodeFile_list:
            malware_edgeFile_path = malware_opcodeFile_path.replace("opcode", "edge")
            self.malware_files.append(file(malware_opcodeFile_path, malware_edgeFile_path))
        for benign_opcodeFile_path in self.benign_opcodeFile_list:
            benign_edgeFile_path = benign_opcodeFile_path.replace("opcode", "edge")
            self.benign_files.append(file(benign_opcodeFile_path, benign_edgeFile_path))
        self.files = self.malware_files + self.benign_files

    """ 
        Extracts node_count different nodes for malwares and also node_count different nodes for benigns. These nodes are the most frequently seen nodes and they are used to start a random walk.
    """
    def extractNodes(self):
        # extract nodes for malware files
        malware_freqs = dict()
        for malware_file in self.malware_files: # calculate the opcode frequencies for malware files
            malware_freqs = malware_file.calculateFrequencies(malware_freqs)
        sorted_malware_freqs = dict(sorted(malware_freqs.items(), key=lambda x: x[1], reverse=True)) # sort malware freqs (descending)
        self.malware_nodes = list(sorted_malware_freqs.keys())[:self.node_count] # get the selected nodes

        # extract nodes for malware files
        benign_freqs = dict()
        for benign_file in self.benign_files:  # calculate the opcode frequencies for malware files
            benign_freqs = benign_file.calculateFrequencies(benign_freqs)
        sorted_benign_freqs = dict(sorted(benign_freqs.items(), key=lambda x: x[1], reverse=True))  # sort malware freqs (descending)
        self.benign_nodes = list(sorted_benign_freqs.keys())[:self.node_count]  # get the selected nodes

    """
        Remove some edges according to the ratio.
    """
    def removeEdges(self):
        for file in self.files:
            source_nodes = list(file.edge_dict.keys()) # nodes that are the source of an edge
            for source_node in source_nodes:
                sum = 0 # summation of the number of edges that starts with "source_node"
                for destination_node in file.edge_dict[source_node]:
                    sum += file.edge_dict[source_node][destination_node]
                percentage = (sum * self.edge_ratio) / 100
                destination_nodes = list(file.edge_dict[source_node].keys())
                for destination_node in destination_nodes:
                    if file.edge_dict[source_node][destination_node] < percentage:
                        del(file.edge_dict[source_node][destination_node])

class soemd:
    """
        :param malware_dataset_directories: malware dataset directories as a string list
        :param benign_dataset_directories: benign dataset directories as a string list
        :param node_count:  number of nodes to extract, default = 15
        :param edge_ratio:  default = 4
        :param sequence_length: length of the random walks, default = 50
        :param sequences_per_node: number of random walks to create per a node. the number of random walks per a sample becomes sequences_per_node*node_count


        The directory hierarchy:

        ---DatasetName
        -------exe        -> this folder contains executable files
        -------opcode     -> this folder (will) contain opcode files
        -------edge       -> this folder (will) contain edge files
    """
    def __init__(self, malware_dataset_directories = [], benign_dataset_directories = [], node_count = 15, edge_ratio = 4, sequence_length = 50, sequences_per_node = 3):
        self.malware_dataset_directories = malware_dataset_directories
        self.benign_dataset_directories = benign_dataset_directories
        self.node_count = node_count
        self.edge_ratio = edge_ratio
        self.sequence_length = sequence_length
        self.sequences_per_node = sequences_per_node
        self.dataset = None # single dataset object, not a list
        self.malware_opcode_file_list = [] # combined opcode file list of malware samples
        self.benign_opcode_file_list = []  # combined opcode file list of benign samples
        self.malware_randomWalks_dict = dict()
        self.benign_randomWalks_dict = dict()
        self.generateOpcodeFiles()
        self.generateEdgeFiles()
        self.generateDataset()

    """
        Generates opcode files.
    """
    def generateOpcodeFiles(self):
        for malware_dataset_directory in self.malware_dataset_directories:
            self.malware_opcode_file_list += disassembler.createOpcodeFiles(malware_dataset_directory)
        for benign_dataset_directory in self.benign_dataset_directories:
            self.benign_opcode_file_list += disassembler.createOpcodeFiles(benign_dataset_directory)

    """
        Generates edge files.
    """
    def generateEdgeFiles(self):
        for malware_dataset_directory in self.malware_dataset_directories:
            graph.generateEdgeFiles(malware_dataset_directory)
        for benign_dataset_directory in self.benign_dataset_directories:
            graph.generateEdgeFiles(benign_dataset_directory)

    """
        Creates dataset objects.
    """
    def generateDataset(self):
        self.dataset = dataset(self.malware_opcode_file_list, self.benign_opcode_file_list, self.node_count, self.edge_ratio)


    """
        Generates sequences
    """
    def generateSequence(self, sample, last_used_opcode):
        seq = [last_used_opcode]
        for j in range(self.sequence_length - 1):
            if last_used_opcode not in sample.edge_dict.keys():
                return None
            possible_destinations = list(sample.edge_dict[last_used_opcode].keys())
            if len(possible_destinations) == 0:
                return None
            randomnumber = random.randint(0, len(possible_destinations) - 1)
            next_opcode = possible_destinations[randomnumber]
            randomnumbers = []
            randomnumbers.append(randomnumber)
            while (j != self.sequence_length - 2 and next_opcode not in sample.edge_dict.keys()):
                if (len(randomnumbers) == len(possible_destinations)):
                    return None
                while (randomnumber not in randomnumbers):
                    randomnumber = random.randint(0, len(possible_destinations) - 1)
                randomnumbers.append(randomnumber)
                next_opcode =  possible_destinations[randomnumber]
            seq.append(next_opcode)
            last_used_opcode = next_opcode
        return seq


    """
        Generates random walks with the help of generateSequence
    """
    def generateRandomWalks(self):
        print("Generating random walks")
        # generate random walks for malwares
        for malware_sample in self.dataset.malware_files:
            self.malware_randomWalks_dict[malware_sample.file_hash] = []
            for starting_node_index in range(self.node_count):
                if self.dataset.malware_nodes[starting_node_index] in malware_sample.edge_dict.keys():
                    starting_node = self.dataset.malware_nodes[starting_node_index]
                else:
                    starting_node = list(malware_sample.edge_dict.keys())[starting_node_index]  # if node was found in the sample (sample is a zero-day malware), then the first opcode of the file is the starting node
                for i in range(self.sequences_per_node):
                    seq = self.generateSequence(malware_sample, starting_node)
                    trials = 0
                    while(seq == None and trials < 10):
                        seq = self.generateSequence(malware_sample, starting_node)
                        trials += 1
                    if seq != None and len(seq) == self.sequence_length:
                        self.malware_randomWalks_dict[malware_sample.file_hash].append(seq)
            if(len(self.malware_randomWalks_dict[malware_sample.file_hash]) != self.sequences_per_node*self.node_count):
                del(self.malware_randomWalks_dict[malware_sample.file_hash])
        # generate random walks for malwares
        for benign_sample in self.dataset.benign_files:
            self.benign_randomWalks_dict[benign_sample.file_hash] = []
            for starting_node_index in range(self.node_count):
                if self.dataset.benign_nodes[starting_node_index] in benign_sample.edge_dict.keys():
                    starting_node = self.dataset.benign_nodes[starting_node_index]
                else:
                    starting_node = list(benign_sample.edge_dict.keys())[0]  # if node was found in the sample (sample is a zero-day benign), then the first opcode of the file is the starting node
                for i in range(self.sequences_per_node):
                    seq = self.generateSequence(benign_sample, starting_node)
                    trials = 0
                    while (seq == None and trials < 10):
                        seq = self.generateSequence(benign_sample, starting_node)
                        trials += 1
                    if seq != None and len(seq) == self.sequence_length:
                        self.benign_randomWalks_dict[benign_sample.file_hash].append(seq)
            if(len(self.benign_randomWalks_dict[benign_sample.file_hash]) != self.sequences_per_node*self.node_count):
                del(self.benign_randomWalks_dict[benign_sample.file_hash])

"""
    Generates train and test samples. Since every file sample has a number of (45, by default) walks, 
    the walks of a single file should be saved all together for testing. Therefore, the test data is returned as dictionaries.
    Each dict key represents a single file. The value of it is the list of walks. 
    :param malware_dict: malware_dict created by soemd class.
    :param benign_dict: benign_dict created by soemd class.
    :param train_ratio: percentage of train data (0.9, 0.8 etc)
"""
def train_test_split(malware_dict, benign_dict, train_ratio):
    hash_codes = list(malware_dict.keys()) + list(benign_dict.keys())
    X_train = []
    y_train = []
    X_test = dict()
    y_test = []

    random.shuffle(hash_codes) # shuffle
    train_size = int(train_ratio*len(hash_codes))

    # train data
    for hash_code in hash_codes[:train_size]:
        # if malware
        if hash_code in malware_dict.keys():
            for walk in malware_dict[hash_code]:
                X_train.append(" ".join(walk))
                y_train.append(1)
        # if benign
        else:
            for walk in benign_dict[hash_code]:
                X_train.append(" ".join(walk))
                y_train.append(0)

    #test data
    for hash_code in hash_codes[:train_size]:
        X_test[hash_code] = []
        # if malware
        if hash_code in malware_dict.keys():
            for walk in malware_dict[hash_code]:
                X_test[hash_code].append(" ".join(walk))
            y_test.append(1)
        else:
            for walk in benign_dict[hash_code]:
                X_test[hash_code].append(" ".join(walk))
            y_test.append(0)
    return np.array(X_train), np.array(y_train), X_test, y_test


"""
    Function to test a trained model
"""
def test_model (model, X_test, y_test, w2v_model, walks_per_file = 45):
    X_test_vectors = []
    for key in X_test.keys():
        for walk in X_test[key]:
            X_test_vectors.append(w2v_model.getSampleVectors(walk))
    X_test_vectors = np.array(X_test_vectors)
    y_pred = model.predict(X_test_vectors)

    TN = 0
    TP = 0
    FN = 0
    FP = 0

    number_of_files = len(y_test)

    for i in range(number_of_files):
        malware_decisions = 0
        for j in range(walks_per_file):
            walk_index = i * walks_per_file + j
            if (y_pred[walk_index] >= 0.5):
                malware_decisions += 1
        if malware_decisions > 22:
            prediction = 1
        else:
            prediction = 0

        if prediction == 1:
            if y_test[i] == 1:
                TP += 1
            else:
                FP += 1
        else:
            if y_test[i] == 1:
                FN += 1
            else:
                TN += 1
    acc = (TP + TN) / (TP + TN + FP + FN)
    tpr = (TP) / (TP + FN)
    return acc, tpr



if __name__ == "__main__":
    soemd_object = soemd([""], [""])
    soemd_object.generateRandomWalks()
    X_train, y_train, X_test, y_test = train_test_split(soemd_object.malware_randomWalks_dict, soemd_object.benign_randomWalks_dict, 0.9)
    w2v_model = w2v.w2v(sentences=X_train, vector_size=4)
    X_train = w2v_model.getDatasetVectors()

    model = train_model(X_train, y_train) # assuming we have a train_model function
    acc, tpr = test_model (model, X_test, y_test, w2v_model)
    print("Accuracy:", acc, "and TPR:", tpr)

