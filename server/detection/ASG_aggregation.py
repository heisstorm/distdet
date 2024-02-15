from gensim.models import Word2Vec
from nltk.tokenize import word_tokenize

if __name__ == '__main__':

    # Sample sentences
    sentence1 = "The cat is on the mat"
    sentence2 = "A dog sits on the rug"
    sentence3 = "Birds are chirping in the trees"

    # Tokenize sentences into words
    tokenized_sentence1 = word_tokenize(sentence1.lower())
    tokenized_sentence2 = word_tokenize(sentence2.lower())
    tokenized_sentence3 = word_tokenize(sentence3.lower())

    # Create a list of tokenized sentences
    tokenized_sentences = [tokenized_sentence1, tokenized_sentence2, tokenized_sentence3]

    # Train a Word2Vec model
    model = Word2Vec(tokenized_sentences, vector_size=100, window=5, min_count=1, workers=4)

    # Function to calculate sentence similarity using Word2Vec
    def sentence_similarity(sentence1, sentence2):
        vector1 = sum([model.wv[word] for word in sentence1 if word in model.wv])
        vector2 = sum([model.wv[word] for word in sentence2 if word in model.wv])

        # Calculate cosine similarity
        similarity = sum(vector1 * vector2) / (sum(vector1 ** 2) ** 0.5 * sum(vector2 ** 2) ** 0.5)
        return similarity

    # Calculate similarity between sentences
    similarity_score_1_2 = sentence_similarity(tokenized_sentence1, tokenized_sentence2)
    similarity_score_1_3 = sentence_similarity(tokenized_sentence1, tokenized_sentence3)
    similarity_score_2_3 = sentence_similarity(tokenized_sentence2, tokenized_sentence3)

    print(f"Similarity between Sentence 1 and Sentence 2: {similarity_score_1_2}")
    print(f"Similarity between Sentence 1 and Sentence 3: {similarity_score_1_3}")
    print(f"Similarity between Sentence 2 and Sentence 3: {similarity_score_2_3}")
