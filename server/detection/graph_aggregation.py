from gensim.models import Word2Vec
from nltk.tokenize import word_tokenize
from scipy.cluster.hierarchy import linkage, dendrogram
import matplotlib.pyplot as plt
import os

if __name__ == '__main__':
    # Sample sentences
    sentences = []

    for root, dirs, files in os.walk('ASG'):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
                sentences.append(file_content)

    # Tokenize sentences
    tokenized_sentences = [word_tokenize(sentence.lower()) for sentence in sentences]

    # Train a Word2Vec model
    model = Word2Vec(tokenized_sentences, vector_size=100, window=5, min_count=2, workers=4)

    # Function to calculate sentence similarity using Word2Vec
    def sentence_similarity(sentence1, sentence2):
        vector1 = sum([model.wv[word] for word in sentence1 if word in model.wv])
        vector2 = sum([model.wv[word] for word in sentence2 if word in model.wv])

        # Calculate cosine similarity
        similarity = sum(vector1 * vector2) / (sum(vector1 ** 2) ** 0.5 * sum(vector2 ** 2) ** 0.5)
        return similarity

    # Create a similarity matrix
    similarity_matrix = [[sentence_similarity(sent1, sent2) for sent2 in tokenized_sentences] for sent1 in tokenized_sentences]

    # Perform hierarchical clustering
    Z = linkage(similarity_matrix, 'ward')  # 'ward' method minimizes the variance between clusters
    dendrogram(Z, labels=sentences, orientation='right')

    plt.title('Hierarchical Clustering of Sentences based on Word2Vec Similarity')
    plt.xlabel('Dissimilarity')
    plt.show()
