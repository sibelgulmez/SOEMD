from lib import disassembler, graph, w2v, dl
import csv, random, numpy, os, time
import numpy as np

class file:
    def __init__(self, opcode_file_path, edge_file_path, edge_ratio):
        self.opcode_file_path = opcode_file_path
        if not str(opcode_file_path).endswith(".opcode"):
            self.opcode_file_path += ".opcode"
        self.file_hash = os.path.splitext(os.path.basename(opcode_file_path))[0]
        self.edge_file_path = edge_file_path
        if not str(edge_file_path).endswith(".edge"):
            self.edge_file_path += ".edge"
        self.edge_ratio = edge_ratio
        self.disassembler_object = disassembler.opcode(opcode_file_path)

    def calculateFrequencies(self, frequency_dict):
        """
            Updates the frequency_dict with the new file whose opcode file path is given with opcode_file_path.
        """
        disassembler_object = disassembler.opcode(self.opcode_file_path)
        disassembler_object.readOpcodeFromFile(self.opcode_file_path)
        opcodes_as_list =  disassembler_object.opcode_sequence_as_list

        for opcode in opcodes_as_list:
            if opcode in frequency_dict.keys():
                frequency_dict[opcode] +=1
            else:
                frequency_dict[opcode] = 1
        del(opcodes_as_list)
        del(disassembler_object)
        return frequency_dict


    def generateEdgeDict(self):
        """
            Reads the edge file and generates edge dictionary.
        """
        edge_dict = dict()
        f = open(self.edge_file_path, "r")
        content = f.readlines()
        f.close()

        if len(content)>0 and content[-1] == "": # if the last line is empty, delete it
            content = content [:-1]
        for c in content:
            edge, frequency = c.split(" ")
            edge_source, edge_destination = edge.split("->")
            if edge_source in edge_dict.keys():
                edge_dict[edge_source][edge_destination] = int(frequency)
            else:
                edge_dict[edge_source] = dict()
                edge_dict[edge_source][edge_destination] = int(frequency)
        return edge_dict


    def removeEdges(self, edge_dict):
        """
            Remove some edges according to the ratio.
        """
        source_nodes = list(edge_dict.keys())  # nodes that are the source of an edge
        for source_node in source_nodes:
            sum = 0  # summation of the number of edges that starts with "source_node"
            for destination_node in edge_dict[source_node]:
                sum += edge_dict[source_node][destination_node]
            percentage = (sum * self.edge_ratio) / 100
            destination_nodes = list(edge_dict[source_node].keys())
            for destination_node in destination_nodes:
                if edge_dict[source_node][destination_node] < percentage:
                    del (edge_dict[source_node][destination_node])
        return edge_dict


    def getCleanedEdges(self):
        edge_dict = self.generateEdgeDict()
        edge_dict = self.removeEdges(edge_dict)
        return edge_dict

class dataset:
    """
        :param malware_opcodeFile_list: list, paths of the opcode files of the malware executables
        :param benign_opcodeFile_list: list, paths of the opcode files of the benign executables
        :param node_count:  number of nodes to extract, default = 15
        :param edge_ratio:  default = 4
    """
    def __init__(self, malware_opcodeFile_list = [], benign_opcodeFile_list = [], node_count = 15, edge_ratio = 4, create_nodes = True):
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
        if create_nodes:
            self.extractNodes()
        else:
            self.readNodes()



    def generateFileObjects(self):
        """
            Generates an edge dictionary for each file and fill them into malware_files and benign_files
        """
        print("Generating file objects.")
        for malware_opcodeFile_path in self.malware_opcodeFile_list:
            malware_edgeFile_path = malware_opcodeFile_path.replace("opcode", "edge")
            self.malware_files.append(file(malware_opcodeFile_path, malware_edgeFile_path, self.edge_ratio))
        for benign_opcodeFile_path in self.benign_opcodeFile_list:
            benign_edgeFile_path = benign_opcodeFile_path.replace("opcode", "edge")
            self.benign_files.append(file(benign_opcodeFile_path, benign_edgeFile_path, self.edge_ratio))
        self.files = self.malware_files + self.benign_files


    def extractNodes(self):
        """
            Extracts node_count different nodes for malwares and also node_count different nodes for benigns. These nodes are the most frequently seen nodes and they are used to start a random walk.
        """
        print("Extracting nodes.")
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
        self.save_nodes()

    def save_nodes(self):
        """
        save the nodes in a file for easy use.
        :return:
        """
        f = open("nodes.txt", "w")
        for node in self.malware_nodes:
            f.write(node + "\n")
        for node in self.benign_nodes:
            f.write(node + "\n")
        f.close()

    def readNodes(self):
        """
        if nodes are already generated and saved, read them.
        :return:
        """
        print("Reading nodes.")
        f = open("nodes.txt", "r")
        content = f.read().split("\n")
        f.close()
        self.malware_nodes = content[:self.node_count]
        self.benign_nodes = content[self.node_count:self.node_count*2]


class soemd:
    """
        :param malware_dataset_directories: malware dataset directories as a string list
        :param benign_dataset_directories: benign dataset directories as a string list
        :param node_count:  number of nodes to extract, default = 15
        :param edge_ratio:  default = 4
        :param sequence_length: length of the random walks, default = 50
        :param sequences_per_node: number of random walks to create per a node. the number of random walks per a sample becomes sequences_per_node*node_count
        :param train_size: percentage of train data


        The directory hierarchy:

        ---DatasetName
        -------exe        -> this folder contains executable files
        -------opcode     -> this folder (will) contain opcode files
        -------edge       -> this folder (will) contain edge files
    """
    def __init__(self, malware_dataset_directories = [], benign_dataset_directories = [], create_nodes = True, node_count = 15, edge_ratio = 4, sequence_length = 50, sequences_per_node = 3, train_size = 0.9):
        self.malware_dataset_directories = malware_dataset_directories
        self.benign_dataset_directories = benign_dataset_directories
        self.create_nodes = create_nodes
        self.node_count = node_count
        self.edge_ratio = edge_ratio
        self.sequence_length = sequence_length
        self.sequences_per_node = sequences_per_node
        self.train_size = train_size
        self.X_train = []
        self.y_train = []
        self.X_test = dict()
        self.y_test = []
        self.dataset = None # single dataset object, not a list
        self.malware_opcode_file_list = [] # combined opcode file list of malware samples
        self.benign_opcode_file_list = []  # combined opcode file list of benign samples
        self.generateOpcodeFiles()
        self.generateEdgeFiles()
        self.generateDataset()


    def generateOpcodeFiles(self):
        """
            Generates opcode files.
        """
        for malware_dataset_directory in self.malware_dataset_directories:
            self.malware_opcode_file_list += disassembler.createOpcodeFiles(malware_dataset_directory)
        for benign_dataset_directory in self.benign_dataset_directories:
            self.benign_opcode_file_list += disassembler.createOpcodeFiles(benign_dataset_directory)

    def generateEdgeFiles(self):
        """
            Generates edge files.
        """
        for malware_dataset_directory in self.malware_dataset_directories:
            graph.generateEdgeFiles(malware_dataset_directory)
        for benign_dataset_directory in self.benign_dataset_directories:
            graph.generateEdgeFiles(benign_dataset_directory)


    def generateDataset(self):
        """
            Creates dataset object.
        """
        self.dataset = dataset(self.malware_opcode_file_list, self.benign_opcode_file_list, self.node_count, self.edge_ratio, self.create_nodes)

    def generateSequence(self, edge_dict, last_used_opcode):
        """
            Generates sequences
        """
        seq = [last_used_opcode]
        for j in range(self.sequence_length - 1):
            if last_used_opcode not in edge_dict.keys():
                return None
            possible_destinations = list(edge_dict[last_used_opcode].keys())
            if len(possible_destinations) == 0:
                return None
            randomnumber = random.randint(0, len(possible_destinations) - 1)
            next_opcode = possible_destinations[randomnumber]
            randomnumbers = []
            randomnumbers.append(randomnumber)

            # eğer seçilen opcode ve son 10 opcode aynı ise farklı bir opcode'a gitsin.
            flag = True if len(seq) > 10 and list(set((seq[::-1])[:10])) == [next_opcode] else False
            while (j != self.sequence_length - 2 and next_opcode not in edge_dict.keys() or flag):
                if (len(randomnumbers) == len(possible_destinations)):
                    return None
                while (randomnumber not in randomnumbers):
                    randomnumber = random.randint(0, len(possible_destinations) - 1)
                randomnumbers.append(randomnumber)
                next_opcode =  possible_destinations[randomnumber]
                flag = True if len(seq) > 10 and list(set((seq[::-1])[:10])) == [next_opcode] else False
            seq.append(next_opcode)
            last_used_opcode = next_opcode
        return seq
    def randomWalkGeneration_helper_train(self, file_list, isMalware):
        data = []
        labels = []
        if isMalware:
            nodes = self.dataset.malware_nodes
        else:
            nodes = self.dataset.benign_nodes
        for sample in file_list:
            edge_dict = sample.getCleanedEdges()
            if (len(list(edge_dict.keys()))) == 0:
                continue
            for starting_node_index in range(self.node_count):
                if nodes[starting_node_index] in edge_dict.keys():
                    starting_node = nodes[starting_node_index]
                else:
                    if len(list(edge_dict.keys())) > starting_node_index:
                        starting_node = list(edge_dict.keys())[starting_node_index]  # if node was found in the sample (sample is a zero-day software), then the first opcode of the file is the starting node
                    else:
                        starting_node = list(edge_dict.keys())[0]
                for i in range(self.sequences_per_node):
                    seq = self.generateSequence(edge_dict, starting_node)
                    trials = 0
                    while(seq == None and trials < 10):
                        seq = self.generateSequence(edge_dict, starting_node)
                        trials += 1
                    if seq != None and len(seq) == self.sequence_length:
                        data.append(seq)
                        labels.append(isMalware)
        return data, labels
    def randomWalkGeneration_helper_test(self, file_list, isMalware):
        data = dict()
        labels = []
        nodes = self.dataset.malware_nodes + self.dataset.benign_nodes
        for sample in file_list:
            data[sample.file_hash] = []
            edge_dict = sample.getCleanedEdges()
            if (len(list(edge_dict.keys()))) == 0:
                continue
            for starting_node_index in range(self.node_count):
                if nodes[starting_node_index] in edge_dict.keys():
                    starting_node = nodes[starting_node_index]
                else:
                    if len(list(edge_dict.keys())) > starting_node_index:
                        starting_node = list(edge_dict.keys())[starting_node_index]  # if node was found in the sample (sample is a zero-day software), then the first opcode of the file is the starting node
                    else:
                        starting_node = list(edge_dict.keys())[0]
                for i in range(self.sequences_per_node):
                    seq = self.generateSequence(edge_dict, starting_node)
                    trials = 0
                    while(seq == None and trials < 10):
                        seq = self.generateSequence(edge_dict, starting_node)
                        trials += 1
                    if seq != None and len(seq) == self.sequence_length:
                        data[sample.file_hash].append(seq)
            labels.append(isMalware)
        return data, labels
    def generateRandomWalks(self):
        """
            Generates random walks with the help of generateSequence
        """
        print("Generating random walks. ", end="")
        random.shuffle(self.dataset.malware_files)
        random.shuffle(self.dataset.benign_files)

        malware_train_size = int(len(self.dataset.malware_files)*self.train_size)
        benign_train_size = int(len(self.dataset.benign_files)*self.train_size)


        #Training
        # generate random walks for malwares
        malware_x_train, malware_y_train = self.randomWalkGeneration_helper_train(self.dataset.malware_files[:malware_train_size], 1)
        # generate random walks for benigns
        benign_x_train, benign_y_train = self.randomWalkGeneration_helper_train(self.dataset.benign_files[:benign_train_size], 0)

        self.X_train = malware_x_train + benign_x_train
        self.y_train = malware_y_train + benign_y_train

        # Testing
        # generate random walks for malwares
        malware_x_test, malware_y_test = self.randomWalkGeneration_helper_test(self.dataset.malware_files[malware_train_size:], 1)
        # generate random walks for benigns
        benign_x_test, benign_y_test = self.randomWalkGeneration_helper_test(self.dataset.benign_files[benign_train_size:], 0)

        self.X_test = malware_x_test.update(benign_x_test)
        self.y_test = malware_y_test + benign_y_test


def test_model (model, X_test, y_test, w2v_model):
    """
        Function to test a trained model
    """
    X_test_vectors = []
    seq_counts = []
    for key in X_test.keys():
        seq_counts.append(len(X_test[key]))
        for walk in X_test[key]:
            X_test_vectors.append(w2v_model.getSampleVectors(walk))
    X_test_vectors = np.array(X_test_vectors)
    y_pred = model.predict(X_test_vectors)

    TN = 0
    TP = 0
    FN = 0
    FP = 0


    for i in range(seq_counts):
        malware_decisions = 0
        for j in range(seq_counts[i]):
            walk_index = i * seq_counts[i] + j
            if (y_pred[walk_index] >= 0.5):
                malware_decisions += 1
        if malware_decisions >= seq_counts[i]/2:
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
    malware_datasets = ["dataset_directory"]                        ]
    benign_datasets = ["dataset_directory" ]
    soemd_object = soemd(malware_datasets, benign_datasets, create_nodes = True)
    soemd_object.generateRandomWalks()
    X_train, y_train, X_test, y_test = soemd_object.X_train, soemd_object.y_train, soemd_object.X_test, soemd_object.y_test #train_test_split(soemd_object.malware_randomWalks_dict, soemd_object.benign_randomWalks_dict, 0.50)
    w2v_model = w2v.w2v(sentences=X_train, create_model = True)
    X_train = w2v_model.getDatasetVectors()
    model = cnn_model() # assuming we have a cnn model
    model.fit(X_train, y_train, epochs = epochs, batch_size=batch_size) # assuming we have the parameters
    acc, tpr = test_model (model, X_test, y_test, w2v_model)
    print("Accuracy:", acc, "and TPR:", tpr)
