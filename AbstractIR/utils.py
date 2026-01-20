from .ir import SizeExpr

def node_text(node, code):
    return code[node.start_byte:node.end_byte].decode()

def make_const(val):
    return SizeExpr(kind='CONST', value=int(val))

def make_var(name):
    return SizeExpr(kind='VAR', value=name)