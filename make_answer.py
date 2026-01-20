import os
import json
import faiss
import pandas as pd
from dotenv import load_dotenv
from tree_sitter_languages import get_parser
from AbstractIR.builder import AbstractBuilder
from Retriever.model import GraphCodeBERTEmbedder
from LLM.model import ValidatorLLM

def normalize(vec):
    vec = vec.astype('float32')
    faiss.normalize_L2(vec.reshape(1, -1))
    return vec

def search(query_emb, k=3):
    q = normalize(query_emb)

    scores, ids = index.search(q.reshape(1, -1), k)

    results = []
    for idx, score in zip(ids[0], scores[0]):
        if idx == -1:
            continue
        results.append({
            'score': float(score),
            **meta[idx]
        })
        
    return results

TEST_PATH = './Devign/devign_testcase.csv'
KNOWLEDGE_PATH = './KnowledgeBase/kb.faiss'
META_PATH = './KnowledgeBase/kb_meta.jsonl'

if __name__ == '__main__':
    ast_parser = get_parser('c')
    embedder = GraphCodeBERTEmbedder()

    index = faiss.read_index(KNOWLEDGE_PATH)

    meta = []
    with open(META_PATH, 'r', encoding='utf-8') as f:
        for line in f:
            meta.append(json.loads(line))

    df = pd.read_csv(TEST_PATH)

    for i in [1, 3, 5]:
        answer_results = []
        for idx, row in df.iterrows():
            code = row.get('func')
            code_bytes = code.encode('utf-8')
            tree = ast_parser.parse(code_bytes)
            root = tree.root_node
            with open(f'./debug/code_debug.c', 'w', encoding='utf-8') as f:
                f.write(str(code))
            air_parser = AbstractBuilder(code=code_bytes)
            abstract_ir = air_parser.parse(root)
            air_parser.truncate(budget=0)
            abstract_ir = [str(e) for e in air_parser.events]
            gcb_input = air_parser.get_gcb_input()

            embedding = embedder.embed(gcb_input.get('tokens'), gcb_input.get('dfg'))
            result = search(embedding, k=i)

            answer_results.append({
                'func': code,
                'func_abstract_ir': abstract_ir,
                'retrieved_scores': [r.get('score') for r in result],
                'retrieved_cwe': [r.get('cwe') for r in result],
                'retrieved_func': [r.get('func') for r in result],
                'retrieved_abstract_ir': [r.get('abstract-ir') for r in result],
                'target': row.get('target')
            })
            print(f'Making answers dataset... [{idx + 1}]')
        
        out_df = pd.DataFrame(answer_results)
        out_df.to_csv(f'abstract_ir_eval_ready_{i}_documents.csv', index=False)

