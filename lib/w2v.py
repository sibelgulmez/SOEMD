from gensim.models import Word2Vec
import numpy as np
import os

""" A class to create a w2v model and get the vectors"""
class w2v:
    """
        :param sentences: string array of sentences (2d list of the whole dataset)
        :param sequence_length: length of the sequences (in this implementation, the sequence length is constant)
        :param vector_size: window size of the w2v model
        :param model_name: optional, file name to save model (should include .bin extension)
    """
    def __init__(self, sentences, sequence_length = 50, vector_size = 300, model_name="word2vec_model.bin"):
        self.sentences = sentences
        self.sequence_length = sequence_length
        self.vector_size = vector_size
        self.model_name = model_name
        self.w2v_model = None
        self.createModel()
        self.saveModel()

    """ creates a w2v model by using the input strings """
    def createModel(self):
        workers = 4 if os.cpu_count() == None else os.cpu_count()
        self.w2v_model = Word2Vec(sentences=self.sentences, vector_size=self.vector_size, sg=0, min_count=1, workers=workers)
        self.w2v_model.init_sims(replace=True)

    """ saves the w2v model """
    def saveModel(self):
        self.w2v_model.save(self.model_name)

    """ gets vectors of the whole dataset and returns them as a numpy array """
    def getDatasetVectors(self):
        sentence_vectors = np.zeros((len(self.sentences), self.sequence_length, self.vector_size)) # empty numpy array
        for i, opcode_seq in enumerate(self.sentences): # filling the empty array
            for j in range(0, self.sequence_length):
                if (j < len(self.sentences[i])):
                    sentence_vectors[i][j] = self.w2v_model.wv[str((self.sentences[i][j]))]
        return sentence_vectors # returning numpy array

    """ gets vectors of a new sample and returns them as a numpy array """
    def getSampleVectors(self, sample):
        vectors = np.zeros((self.sequence_length, self.vector_size)) # empty numpy array
        for i in range(0, self.sequence_length):
            try:
                vectors[i] = self.w2v_model.wv[sample[i]]
            except:
                vectors[i] = np.zeros((self.vector_size))
        return vectors # returning numpy array
