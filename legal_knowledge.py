import os
import re
import pickle
import pdfplumber
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np

class LegalKnowledgeBase:
    def __init__(self, model_name='all-MiniLM-L6-v2', index_path='legal_index.faiss', chunks_path='legal_chunks.pkl'):
        self.model = SentenceTransformer(model_name)
        self.index = None
        self.chunks = []
        self.index_path = index_path
        self.chunks_path = chunks_path
        self.embedding_dim = 384
        
        # Try to load existing index
        self.load()
    
    def extract_text_from_pdf(self, pdf_path):
        """Extract text from PDF using pdfplumber."""
        text = ""
        try:
            with pdfplumber.open(pdf_path) as pdf:
                for page in pdf.pages:
                    text += page.extract_text() or ""
        except Exception as e:
            print(f"Error reading {pdf_path}: {e}")
        return text
    
    def chunk_text(self, text, chunk_size=800, overlap=100):
        """Split text into overlapping chunks."""
        chunks = []
        text = re.sub(r'\s+', ' ', text).strip()
        sentences = re.split(r'(?<=[.!?])\s+', text)
        current_chunk = ""
        for sent in sentences:
            if len(current_chunk) + len(sent) < chunk_size:
                current_chunk += " " + sent
            else:
                if current_chunk:
                    chunks.append(current_chunk.strip())
                overlap_sentences = current_chunk.split('.')[-2:] if current_chunk else []
                current_chunk = " ".join(overlap_sentences) + " " + sent
        if current_chunk:
            chunks.append(current_chunk.strip())
        return chunks
    
    def load_documents(self, folder_path):
        """Load all PDFs from folder and build index."""
        all_chunks = []
        for filename in os.listdir(folder_path):
            if filename.endswith('.pdf'):
                print(f"Processing {filename}...")
                pdf_path = os.path.join(folder_path, filename)
                text = self.extract_text_from_pdf(pdf_path)
                if text:
                    chunks = self.chunk_text(text)
                    for chunk in chunks:
                        all_chunks.append({
                            'source': filename,
                            'text': chunk
                        })
        if not all_chunks:
            print("No text extracted. Check your PDFs.")
            return False
        
        self.chunks = all_chunks
        self.build_index()
        return True
    
    def build_index(self):
        texts = [c['text'] for c in self.chunks]
        embeddings = self.model.encode(texts, convert_to_numpy=True)
        self.embedding_dim = embeddings.shape[1]
        self.index = faiss.IndexFlatL2(self.embedding_dim)
        self.index.add(embeddings.astype(np.float32))
        faiss.write_index(self.index, self.index_path)
        with open(self.chunks_path, 'wb') as f:
            pickle.dump(self.chunks, f)
        print(f"Index built with {len(self.chunks)} chunks.")
    
    def load(self):
        if os.path.exists(self.index_path) and os.path.exists(self.chunks_path):
            try:
                self.index = faiss.read_index(self.index_path)
                with open(self.chunks_path, 'rb') as f:
                    self.chunks = pickle.load(f)
                print(f"Loaded index with {len(self.chunks)} chunks.")
                return True
            except Exception as e:
                print(f"Error loading index: {e}")
        return False
    
    def query(self, question, top_k=5):
        if self.index is None:
            return []
        query_emb = self.model.encode([question], convert_to_numpy=True).astype(np.float32)
        distances, indices = self.index.search(query_emb, top_k)
        results = []
        for i, idx in enumerate(indices[0]):
            if idx < len(self.chunks):
                results.append({
                    'chunk': self.chunks[idx],
                    'score': float(distances[0][i])
                })
        return results

# Singleton
_legal_kb = None

def get_legal_kb():
    global _legal_kb
    if _legal_kb is None:
        _legal_kb = LegalKnowledgeBase()
    return _legal_kb