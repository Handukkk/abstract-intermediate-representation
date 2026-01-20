import os
import re
import sys
import csv
import json
import faiss

from tree_sitter_languages import get_parser
from AbstractIR.builder import AbstractBuilder
# from Retriever.model import GraphCodeBERTEmbedder

BUFFER_OVERFLOW_CWES = {
    'CWE-119',  # Improper Restriction of Operations within the Bounds of a Memory Buffer
    'CWE-120',  # Classic Buffer Overflow
    'CWE-121',  # Stack-based Buffer Overflow
    'CWE-122',  # Heap-based Buffer Overflow
    'CWE-124',  # Buffer Underwrite
    'CWE-125',  # Out-of-bounds Read
    'CWE-787',  # Out-of-bounds Write (modern replacement)
}

def stream_csv_fast(path):
    csv.field_size_limit(64 * 1024 * 1024)

    with open(path, 'r', encoding='utf-8', errors='ignore', newline='') as f:
        reader = csv.reader(f)
        header = next(reader)

        idx = {name: i for i, name in enumerate(header)}

        func_i  = idx['func']

        for row in reader:
            yield {
                'func': row[func_i],
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

def subtree_contains(node, predicate):
    if predicate(node):
        return True

    for child in node.children:
        if subtree_contains(child, predicate):
            return True

    return False

def has_error_anywhere(fn_node):
    return subtree_contains(fn_node, lambda n: n.type == "ERROR")

def has_macro_anywhere(fn_node):
    return subtree_contains(
        fn_node,
        lambda n: n.type in {
            "macro_type_specifier",
            "preproc_call",
            "preproc_def",
            "preproc_function_def",
        }
    )

def has_compound_body(fn_node):
    return any(c.type == "compound_statement" for c in fn_node.children)

def accept_function(fn_node):
    if not has_compound_body(fn_node):
        return False

    if has_error_anywhere(fn_node):
        return False

    if has_macro_anywhere(fn_node):
        return False

    return True

if __name__ == '__main__':
    total = 0
    print('[+] Start Testing...')
    for s in stream_csv_fast('./Devign/devign_testcase.csv'):
        code = s.get('func')

        code_bytes = code.encode('utf-8')
        ast_parser = get_parser('c')
        tree = ast_parser.parse(code_bytes)
        root = tree.root_node
        with open('./debug/code.c', 'w') as f:
            f.write(code)

        ir_builder = AbstractBuilder(code=code_bytes)
        ir_builder.parse(root)
        ir_builder.truncate()
        gcb_input = ir_builder.get_gcb_input()

        total += 1
        print(f'[+] Data tested! [{total}]')

    print('[+] Finished testing')