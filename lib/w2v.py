from gensim.models import Word2Vec
import numpy as np
import os


class w2v:
    """
        A class to create a w2v model and get the vectors
        
        :param sentences: string array of sentences (2d list of the whole dataset)
        :param sequence_length: length of the sequences (in this implementation, the sequence length is constant)
        :param vector_size: window size of the w2v model
        :param model_name: optional, file name to save model (should include .bin extension)
    """
    def __init__(self, sentences, sequence_length = 50, vector_size = 300, model_name="word2vec_model.bin", create_model = True):
        self.sentences = sentences
        self.sequence_length = sequence_length
        self.vector_size = vector_size
        self.model_name = model_name
        self.w2v_model = None
        if create_model:
            self.createModel()
            self.saveModel()
        else:
            self.loadModel()


    def loadModel(self):
        self.w2v_model = Word2Vec().load("word2vec_model.bin")


    def createModel(self):

        """ creates a w2v model by using the input strings """
        print("Training word2vec model...")
        workers = 4 if os.cpu_count() == None else os.cpu_count()
        self.w2v_model = Word2Vec(sentences=self.sentences, vector_size=self.vector_size, sg=0, min_count=1, workers=workers)
        self.w2v_model.init_sims(replace=True)

    
    def saveModel(self):
        """ saves the w2v model """
        self.w2v_model.save(self.model_name)

    
    def getDatasetVectors(self):
        """ gets vectors of the whole dataset and returns them as a numpy array """
        sentence_vectors = np.zeros((len(self.sentences), self.sequence_length, self.vector_size)) # empty numpy array
        for i, opcode_seq in enumerate(self.sentences): # filling the empty array
            for j in range(0, self.sequence_length):
                if (j < len(self.sentences[i])):
                    sentence_vectors[i][j] = self.w2v_model.wv[str((self.sentences[i][j]))]
        return sentence_vectors # returning numpy array

    
    def getSampleVectors(self, sample):
        """ gets vectors of a new sample and returns them as a numpy array """
        vectors = np.zeros((self.sequence_length, self.vector_size)) # empty numpy array
        for i in range(0, self.sequence_length):
            try:
                vectors[i] = self.w2v_model.wv[sample[i]]
            except:
                vectors[i] = np.zeros((self.vector_size))
        return vectors # returning numpy array
