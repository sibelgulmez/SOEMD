from gensim.models import Word2Vec
import numpy as np

def getvectorsVX (sentences, seqlen, window_size):
    word_2_vec = Word2Vec(sentences=sentences, size=window_size, sg=0, window=10, min_count=1, iter=10, workers=8)
    word_2_vec.init_sims(replace=True)

    sentence_vectors = np.zeros((len(sentences), seqlen, window_size))
    for i, opcode_seq in enumerate(sentences):
        for j in range(0, seqlen):
            if (j< len(sentences[i])):
                sentence_vectors[i][j] = word_2_vec.wv[str((sentences[i][j]))]
    return sentence_vectors
