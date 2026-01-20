import os
import re
import sys
import csv
import json
import faiss

from tree_sitter_languages import get_parser
from AbstractIR.builder import AbstractBuilder
from Retriever.model import GraphCodeBERTEmbedder

FAISS_PATH = './KnowledgeBase/kb.faiss'
META_PATH = './KnowledgeBase/kb_meta.jsonl'

def stream_csv_fast(path):
    csv.field_size_limit(64 * 1024 * 1024)

    with open(path, 'r', encoding='utf-8', errors='ignore', newline='') as f:
        reader = csv.reader(f)
        header = next(reader)

        idx = {name: i for i, name in enumerate(header)}

        func_i  = idx['func']
        cwe_i   = idx['cwe']

        for row in reader:
            yield {
                'func': row[func_i],
                'cwe': row[cwe_i],
            }

def normalize(vec):
    vec = vec.astype("float32")
    faiss.normalize_L2(vec.reshape(1, -1))
    return vec

def load_or_create_index(path, dim):
    if os.path.exists(path):
        print('[+] Loading existing FAISS index')
        return None
    else:
        print('[+] Creating new FAISS index')
        return faiss.IndexFlatIP(dim)

def append_meta(meta_path, record):
    with open(meta_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(record, ensure_ascii=False) + '\n')

if __name__ == '__main__':
    embedder = GraphCodeBERTEmbedder()
    index = load_or_create_index(FAISS_PATH, 768)

    if not index:
        print('[+] Knowledge Base already exist')
        exit()

    if os.path.isfile(META_PATH) and not os.path.isfile(FAISS_PATH):
        os.remove(META_PATH)

    total = 0
    print('[+] Starting...')
    for s in stream_csv_fast('./KnowledgeBase/juliet_dataset.csv'):
        code = s.get('func')

        code_bytes = code.encode('utf-8')
        ast_parser = get_parser('c')
        tree = ast_parser.parse(code_bytes)
        root = tree.root_node

        ir_builder = AbstractBuilder(code=code_bytes)
        ir_builder.parse(root)
        ir_builder.normalize()

        if not ir_builder.events:
            continue

        if not any(e.kind in ('PTR_WRITE', 'PTR_ADVANCE') or str(e.kind).startswith('WRITE_') for e in ir_builder.events):
            continue

        abstract_ir = [str(e) for e in ir_builder.events]

        ir_builder.truncate(budget=120)
        gcb_input = ir_builder.get_gcb_input()
        embedding = embedder.embed(gcb_input.get('tokens'), gcb_input.get('dfg'))

        vec = normalize(embedding)
        index.add(vec.reshape(1, -1))

        metadata = {
            'cwe': s.get('cwe'),
            'func': s.get('func'),
            'abstract-ir': abstract_ir,
        }

        append_meta(META_PATH, metadata)

        total += 1
        print(f'[+] Data found! [{total}]')

    print('[+] Finished collecting data, saving')
    faiss.write_index(index, FAISS_PATH)
    print('[+] Data saved')

