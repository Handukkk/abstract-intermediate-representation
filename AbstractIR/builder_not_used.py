from . import utils
from .ir import SizeExpr, AbstractEvent
from collections import defaultdict

import re
import shortuuid

WRITE_FUNCS = {
    # ===== Always Dangerous / Unbounded =====
    'gets':     {'buf': 0, 'size': None},
    'strcpy':   {'buf': 0, 'size': None},
    'strcat':   {'buf': 0, 'size': None},
    'sprintf':  {'buf': 0, 'size': None},
    'vsprintf': {'buf': 0, 'size': None},

    # ===== Size-Controlled Memory Writes =====
    'memcpy':   {'buf': 0, 'size': 2},
    'memmove':  {'buf': 0, 'size': 2},
    'bcopy':    {'buf': 1, 'size': 2},

    # ===== String Functions (Tricky / Often Misused) =====
    'strncpy':  {'buf': 0, 'size': 2},   # may not null-terminate
    'strncat':  {'buf': 0, 'size': 2},

    # ===== Formatted Output =====
    'snprintf': {'buf': 0, 'size': 1},
    'vsnprintf':{'buf': 0, 'size': 1},

    # ===== Input Functions =====
    'fgets':    {'buf': 0, 'size': 1},
    'gets_s':   {'buf': 0, 'size': 1},   # safer, but still size-dependent

    # ===== POSIX / Syscall Writes =====
    'read':     {'buf': 1, 'size': 2},
    'recv':     {'buf': 1, 'size': 2},
    'recvfrom': {'buf': 1, 'size': 2},
    'recvmsg':  {'buf': 1, 'size': None},  # iovec-based

    # ===== scanf Family (Format-Driven, Treat as Unbounded) =====
    'scanf':    {'buf': 1, 'size': None},
    'sscanf':   {'buf': 2, 'size': None},
    'fscanf':   {'buf': 2, 'size': None},

    # ===== Wide-char variants =====
    'wcscpy':   {'buf': 0, 'size': None},
    'wcsncpy':  {'buf': 0, 'size': 2},
    'swprintf': {'buf': 0, 'size': None},
}

USE_FUNCS = {
    # string sinks
    'puts':  {'buf': 0},
    'printf': {'buf': 1},
    'fprintf': {'buf': 2},
    'strlen': {'buf': 0},
    'strcmp': {'buf': 0},
    'strncmp': {'buf': 0},
    'strchr': {'buf': 0},
    'strstr': {'buf': 0},
}

HEAP_FUNCS = ('malloc', 'calloc', 'realloc')

OP_MAP = {
    # ===== Comparison =====
    '==': 'EQ',
    '!=': 'NE',
    '<':  'LT',
    '<=': 'LE',
    '>':  'GT',
    '>=': 'GE',

    # ===== Logical =====
    '&&': 'AND',
    '||': 'OR',
    '!':  'NOT',

    # ===== Arithmetic =====
    '+':  'ADD',
    '-':  'SUB',
    '*':  'MUL',
    '/':  'DIV',
    '%':  'MOD',

    # ===== Bitwise =====
    '&':  'BIT_AND',
    '|':  'BIT_OR',
    '^':  'BIT_XOR',
    '<<': 'SHL',
    '>>': 'SHR',

    # ===== Assignment (only if you keep it) =====
    '=':  'ASSIGN',
}

TOKEN_RE = re.compile(
    r"""
    ->|==|!=|<=|>=|&&|\|\|      # multi-char operators
    |[(){}\[\]]                # brackets
    |[=<>+\-*/%!]              # single-char operators
    |[A-Za-z_][A-Za-z0-9_]*    # identifiers
    |[0-9]+                    # numbers
    |NULL                      # NULL literal
    """,
    re.VERBOSE
)

EVENT_PRIORITY = {
    'REGION': 100,
    'ALLOC': 100,

    'WRITE': 90,
    'PTR_WRITE': 90,
    'PTR_ADVANCE': 90,

    'LOOP_BEGIN': 70,
    'LOOP_END': 70,

    'CONSTRAINT': 40,
}

def debug(node):
    for i, e in enumerate(node.named_children):
        print(
            f'Type: {e.type}', 
            f'Name: {node.field_name_for_child(i)}'
        )
        print('===========================')

class AbstractBuilder:
    def __init__(self, code: bytes):
        self.code = code
        self.events = []
        self.struct_fields = {}
        self.pointer_vars = []
        self.struct_vars = set()
        self.variable_data_type = {}

    def parse(self, root):
        self._visit(root)
        self.normalize()
        return self.events
    
    def _visit(self, node):
        handler = getattr(self, f'_handle_{node.type}', None)

        if handler:
            return handler(node)

        for child in node.children:
            self._visit(child)

    # ===== START OF HANDLERS =====

# #    ========== Declarations ==========

#     translation_unit
    def _handle_translation_unit(self, node):
        # debug(node)
        for child in node.named_children:
            self._visit(child)

#     function_definition
    def _handle_function_definition(self, node):
        # debug(node)
        declarator = node.child_by_field_name('declarator')
        body = node.child_by_field_name('body')
        
        params_list = self._visit(declarator)
        
        for param in params_list:
            if param is None:
                continue

            param_name = param.get('var_name')
            if param_name in self.pointer_vars:
                normalized_var_name = self.pointer_vars.index(param_name)
                self.events.append(
                    AbstractEvent(
                        kind='REGION',
                        buffer=f'PTR_VAR_{normalized_var_name}',
                        size=SizeExpr(
                            kind='UNKNOWN',
                            value=None
                        ),
                        source='SOURCE_EXTERNAL',
                        location=node.start_byte
                    )
                )

        if body:
            self._visit(body)

#     declaration
    def _handle_declaration(self, node):
        var_type_node = node.child_by_field_name('type')
        var_type_name = self._visit(var_type_node)

        for child in node.children:
            if child.type in (
                'init_declarator',
                'pointer_declarator',
                'array_declarator',
                'function_declarator',
                'identifier',
            ):
                
                var_declarator = self._visit(child)

                var_kind = var_declarator.get('var_kind')
                var_name = var_declarator.get('var_name')
                var_size = var_declarator.get('var_size')
                self.variable_data_type[var_name] = var_type_name

                if var_kind == 'array':
                    if var_size != None:
                        result = var_size
                        size_list = self._flatten_binary_expr(result)

                        list_size = []
                        for r in size_list:
                            if isinstance(r, dict):
                                list_size.append(r.get('var_name'))
                            elif isinstance(r, str):
                                list_size.append(r)
                            elif isinstance(r, int):
                                list_size.append(str(r))

                        size_name = ''.join(list_size)
                        splitted = re.split(r'(\+|-(?!>)|\*|/)', size_name)
                        var_size = ' '.join(splitted)

                        size_expr = SizeExpr(
                                kind='CONST',
                                value=var_size
                            )
                    else:
                        size_expr = SizeExpr(
                                kind='UNKNOWN',
                                value=None
                            )
                    
                    normalized_var_name = self.pointer_vars.index(var_name)
                    self.events.append(
                        AbstractEvent(
                            kind='ALLOC',
                            buffer=f'PTR_VAR_{normalized_var_name}',
                            size=size_expr,
                            location=node.start_byte
                        )
                    )

                for c in node.named_children:
                    if c.type == 'init_declarator':
                        result = self._visit(c)
                        ptr_name = result.get('var_name')
                        
                        if ptr_name in self.pointer_vars:
                            normalized_var_name = self.pointer_vars.index(ptr_name)
                            self.events.append(
                                AbstractEvent(
                                    kind='REGION',
                                    buffer=f'PTR_VAR_{normalized_var_name}',
                                    size=SizeExpr(
                                        kind='CONST',
                                        value=var_size or 'UNKNOWN'
                                    ),
                                    source=var_declarator.get('src') or 'SOURCE_UNKNOWN',
                                    location=node.start_byte
                                )
                            )
                    # print(self._extract(c))

                src_name = var_declarator
                if var_type_node.type == 'struct_specifier':
                    var_type_name = id(var_type_node)
                    var_declarator = var_type_name

                if var_type_node.type == 'primitive_type':
                    if var_name in self.pointer_vars:
                        normalized_var_name = self.pointer_vars.index(var_name)
                        self.events.append(
                                AbstractEvent(
                                    kind='REGION',
                                    buffer=f'PTR_VAR_{normalized_var_name}',
                                    size=SizeExpr(
                                        kind='CONST',
                                        value=var_size or 'UNKNOWN'
                                    ),
                                    source=var_declarator.get('src') or 'SOURCE_UNKNOWN',
                                    location=node.start_byte
                                )
                            )

                if var_type_node.type != 'primitive_type':
                    if var_name in self.pointer_vars:
                        normalized_var_name = self.pointer_vars.index(var_name)
                        self.events.append(
                                AbstractEvent(
                                    kind='REGION',
                                    buffer=f'PTR_VAR_{normalized_var_name}',
                                    size=SizeExpr(
                                        kind='CONST',
                                        value=var_size or 'UNKNOWN'
                                    ),
                                    source=src_name.get('src') or 'SOURCE_UNKNOWN',
                                    location=node.start_byte
                                )
                            )
                    else:
                        try:
                            fields = self.struct_fields[var_type_name]
                        except KeyError:
                            if var_name in self.pointer_vars:
                                normalized_var_name = self.pointer_vars.index(var_name)
                                self.events.append(
                                    AbstractEvent(
                                        kind='ALLOC',
                                        buffer=f'PTR_VAR_{normalized_var_name}',
                                        size=SizeExpr(
                                            kind='UNKNOWN',
                                            value=None
                                        ),
                                        location=node.start_byte
                                    )
                                )
                                return
                            else:
                                return

                        for field_name, field_size in fields:
                            self.events.append(
                                AbstractEvent(
                                    kind='ALLOC',
                                    buffer=f'{var_name}.{field_name}',
                                    size=SizeExpr(
                                        kind='CONST',
                                        value=field_size
                                    ),
                                    location=node.start_byte
                                )
                            )

#     init_declarator
    def _handle_init_declarator(self, node):
        var_declarator_node = node.child_by_field_name('declarator')
        val_node = node.child_by_field_name('value')

        var_declarator = self._visit(var_declarator_node)
        var_val = self._visit(val_node)
        
        var_size = var_declarator.get('var_size')
        if var_val and val_node.type == 'string_literal' and not var_size:
            var_declarator['var_size'] = len(var_val) - 1

        if val_node.type == 'field_expression':
            var_val_list = self._flatten_field_chain(var_val)
            var_val = '->'.join(var_val_list)
            var_declarator['src'] = var_val
        
        if var_declarator_node.type == 'pointer_declarator':
            result = self._flatten_binary_expr(var_val)

            list_src = []
            for r in result:
                if isinstance(r, dict):
                    if 'var_name' in r:
                        list_src.append(r.get('var_name'))
                    elif 'fn_name' in r:
                        fn_name = r.get('fn_name')
                        args = r.get('args')
                        
                        args_list = []
                        for arg in args:
                            if isinstance(arg, dict):
                                args_list.append(arg.get('var_name'))
                            elif isinstance(arg, tuple):
                                flatten = self._flatten_binary_expr(arg)
                                list_arg = []
                                for r in flatten:
                                    if isinstance(r, dict):
                                        list_arg.append(r.get('var_name'))
                                    elif isinstance(r, str):
                                        list_arg.append(r)

                                arg_name = ''.join(list_arg)
                                splitted = re.split(r'(\+|-(?!>)|\*|/)', arg_name)
                                args_list.append(' '.join(splitted))

                        args = ', '.join(args_list)
                        list_src.append(f'{fn_name}({args})')
                elif isinstance(r, str):
                    list_src.append(r)
                elif isinstance(r, list):
                    for sub_r in r:
                        list_src.append(sub_r)

            src_name = ''.join(list_src)
            splitted = re.split(r'(\+|-(?!>)|\*|/)', src_name)
            src_name = ' '.join(splitted)
            var_declarator['src'] = src_name

        return var_declarator 
    
#     primitive_type
    def _handle_primitive_type(self, node):
        return self._extract(node)
    
#     type_identifier
    def _handle_type_identifier(self, node):
        return self._extract(node)

#     struct_specifier
    def _handle_struct_specifier(self, node):
        # debug(node)
        var_type_node = node.child_by_field_name('name')
        var_list = node.child_by_field_name('body')

        if var_type_node:
            var_type = self._extract(var_type_node)
        else:
            var_type = id(node)

        if var_list is None:
            return
        
        fields = []
        for child in var_list.named_children:
            for c in child.named_children:
                if c.type == 'primitive_type':
                    continue

                result = self._visit(c)
                if result is None:
                    continue
                field_name = result.get('var_name')
                field_size = result.get('var_size')

                if field_size:
                    fields.append((field_name, field_size))
        
        self.struct_fields[var_type] = fields

#     union_specifier

#     enum_specifier

# #    ========== Declarators ==========

#     identifier
    def _handle_identifier(self, node):
        return {
            'var_name': self._extract(node),
            'var_kind': 'identifier',
            'var_size': None
        }
    
#     field_identifier
    def _handle_field_identifier(self, node):
        var_name = self._extract(node)
        return {
            'var_name': var_name,
            'var_kind': 'field_identifier',
            'var_size': None
        }

#     pointer_declarator
    def _handle_pointer_declarator(self, node):
        for c in node.named_children:
            if c.type == 'identifier':
                var_name = self._extract(c)
                self.pointer_vars.append(var_name)
                return {
                    'var_name': var_name,
                    'var_kind': 'pointer_identifier',
                    'var_size': None
                }
            if c.type == 'function_declarator':
                return self._visit(c)
            if c.type == 'pointer_declarator':
                return self._visit(c)
            if c.type == 'array_declarator':
                return self._visit(c)

#     array_declarator
    def _handle_array_declarator(self, node):
        var_name_node = node.child_by_field_name('declarator')
        var_size_node = node.child_by_field_name('size')

        result = self._visit(var_name_node)

        if var_size_node:
            var_size = self._visit(var_size_node)
        else:
            var_size = None

        result['var_size'] = var_size
        result['var_kind'] = 'array'
        self.pointer_vars.append(result.get('var_name'))
        return result

#     function_declarator
    def _handle_function_declarator(self, node):
        param_node = node.child_by_field_name('parameters')
        
        if param_node:
            return self._visit(param_node)

#     parameter_list
    def _handle_parameter_list(self, node):
        params_list = []
        for c in node.named_children:
            if c.type == 'parameter_declaration':
                params_list.append(self._visit(c))
        return params_list

#     parameter_declaration
    def _handle_parameter_declaration(self, node):
        for c in node.named_children:
            if c.type == 'pointer_declarator':
                return self._visit(c)

# #    ========== Statements ==========

#     compound_statement

#     expression_statement
    def _handle_expression_statement(self, node):
        for c in node.named_children:
            if c.type == 'assignment_expression':
                result = self._visit(c)
            if c.type == 'call_expression':
                result = self._visit(c)
            if c.type == 'pointer_expression':
                result = self._visit(c)
            if c.type == 'update_expression':
                result = self._visit(c)

#     if_statement
    def _handle_if_statement(self, node):
        condition_node = node.child_by_field_name('condition')
        body_node = node.child_by_field_name('consequence')
        alternative_node = node.child_by_field_name('alternative')

        text = utils.node_text(condition_node, self.code)
        text = self._strip_parens(text)
        
        sub_conds = self._split_logical_conditions(text)

        for sub in sub_conds:
            sub = sub.strip()

            paren_stack = 0
            try:
                left, op, right = self._split_condition(sub)

                # handle left
                left = self._strip_parens(left)
                left_idents = TOKEN_RE.findall(left)
                new_left_indents = []
                for i, left_ident in enumerate(left_idents):
                    if left_ident in ['->', '[', ']', '.', '{', '}']:
                        continue

                    if left_ident == '(':
                        paren_stack += 1
                    elif left_ident == ')':
                        paren_stack -= 1

                    if left_ident in self.pointer_vars:
                        normalized_var_name = self.pointer_vars.index(left_ident)
                        new_left_indents.append(f'PTR_VAR_{normalized_var_name}')
                    elif left_ident in WRITE_FUNCS or left_ident in USE_FUNCS or left_ident in HEAP_FUNCS:
                        new_left_indents.append(f'FUNC_{left_ident}')
                    elif i < len(left_idents) - 1 and left_idents[i+1] == '(' and str(left_ident).isidentifier():
                        new_left_indents.append(f'FUNC_{left_ident}')
                    elif left_ident in OP_MAP and paren_stack == 0:
                        new_left_indents.append(f'OP_{OP_MAP.get(left_ident)}')
                    elif i > 0 and left_idents[i-1] == '->':
                        new_left_indents.append(f'FIELD_{left_ident}')
                    elif i > 0 and left_idents[i-1] == '[':
                        new_left_indents.append(f'IDX_{left_ident}')
                    elif i < len(left_idents) - 1 and left_idents[i+1] != '(' and str(left_ident).isidentifier() and paren_stack == 0:
                        new_left_indents.append(f'VAR_{left_ident}')
                    elif len(left_idents) == 1:
                        new_left_indents.append(f'VAR_{left_ident}')
                    else:
                        continue

                left = ' '.join(new_left_indents)

                # hanlde op
                op = OP_MAP.get(op)
                op = f'OP_{op}'

                # handle right
                if right in ["0", "'\\0'"]:
                    right = 'CONST_ZERO'
                elif right == 'NULL':
                    right = 'PTR_NULL'
                elif right in [str(i) for i in range(1, 9)]:
                    right = f'CONST_{right}'
                else:
                    right = self._strip_parens(right)
                    right_idents = TOKEN_RE.findall(right)
                    new_right_indents = []

                    for i, right_ident in enumerate(right_idents):
                        if right_ident in ['->', '[', ']', '.', '{', '}']:
                            continue
                        
                        if right_ident == '(':
                            paren_stack += 1
                        elif right_ident == ')':
                            paren_stack -= 1

                        if right_ident in self.pointer_vars:
                            normalized_var_name = self.pointer_vars.index(right_ident)
                            new_right_indents.append(f'PTR_VAR_{normalized_var_name}')
                        elif right_ident in WRITE_FUNCS or right_ident in USE_FUNCS or right_ident in HEAP_FUNCS:
                            new_right_indents.append(f'FUNC_{right_ident}')
                        elif i < len(right_idents) - 1 and right_idents[i+1] == '(' and str(right_ident).isidentifier():
                            new_right_indents.append(f'FUNC_{right_ident}')
                        elif right_ident in OP_MAP and paren_stack == 0:
                            new_right_indents.append(f'OP_{OP_MAP.get(right_ident)}')
                        elif i > 0 and right_idents[i-1] == '->':
                            new_right_indents.append(f'FIELD_{right_ident}')
                        elif i > 0 and right_idents[i-1] == '[':
                            new_right_indents.append(f'IDX_{right_ident}')
                        elif i < len(right_idents) - 1 and right_idents[i+1] != '(' and str(right_ident).isidentifier() and paren_stack == 0:
                            new_right_indents.append(f'VAR_{right_ident}')
                        elif len(right_idents) == 1:
                            new_right_indents.append(f'VAR_{right_ident}')
                        else:
                            continue

                    right = ' '.join(new_right_indents)

                self.events.append(
                    AbstractEvent(
                        kind='CONSTRAINT',
                        size=SizeExpr(
                            kind='EXPR',
                            value=(left, op, right)
                        ),
                        location=node.start_byte
                    )
                )

            except:
                left = self._strip_parens(sub)
                left_idents = TOKEN_RE.findall(left)
                new_left_indents = []

                for i, left_ident in enumerate(left_idents):
                    if left_ident in ['->', '[', ']', '.', '{', '}']:
                        continue

                    if left_ident == '(':
                        paren_stack += 1
                    elif left_ident == ')':
                        paren_stack -= 1

                    if left_ident in self.pointer_vars:
                        normalized_var_name = self.pointer_vars.index(left_ident)
                        new_left_indents.append(f'PTR_VAR_{normalized_var_name}')
                    elif left_ident in WRITE_FUNCS or left_ident in USE_FUNCS or left_ident in HEAP_FUNCS:
                        new_left_indents.append(f'FUNC_{left_ident}')
                    elif i < len(left_idents) - 1 and left_idents[i+1] == '(' and str(left_ident).isidentifier():
                        new_left_indents.append(f'FUNC_{left_ident}')
                    elif left_ident in OP_MAP and paren_stack == 0:
                        new_left_indents.append(f'OP_{OP_MAP.get(left_ident)}')
                    elif i > 0 and left_idents[i-1] == '->':
                        new_left_indents.append(f'FIELD_{left_ident}')
                    elif i > 0 and left_idents[i-1] == '[':
                        new_left_indents.append(f'IDX_{left_ident}')
                    elif i < len(left_idents) - 1 and left_idents[i+1] != '(' and str(left_ident).isidentifier() and paren_stack == 0:
                        new_left_indents.append(f'VAR_{left_ident}')
                    elif len(left_idents) == 1:
                        new_left_indents.append(f'VAR_{left_ident}')
                    else:
                        continue

                left = ' '.join(new_left_indents)

                self.events.append(
                    AbstractEvent(
                        kind='CONSTRAINT',
                        size=SizeExpr(
                            kind='EXPR',
                            value=(left, None, None)
                        ),
                        location=node.start_byte
                    )
                )

        if condition_node:
            self._visit(condition_node)

        if body_node:
            self._visit(body_node)

        if alternative_node:
            self._visit(alternative_node)


#     for_statement
    def _handle_for_statement(self, node):
        condition_node = node.child_by_field_name('condition')
        body_node = node.child_by_field_name('body')
        
        try:
            condition_res = self._extract(condition_node)
            condition = self._strip_parens(condition_res)

            sub_conds = re.split(r'\s*(&&|\|\|)\s*', condition)
            all_conds = []
            for sub in sub_conds:
                sub = sub.strip()
                if sub in ['&&', '||']:
                    all_conds.append(f"OP_{OP_MAP.get(sub)}")
                    continue

                paren_stack = 0
                try:
                    left, op, right = self._split_condition(sub)

                    # handle left
                    left = self._strip_parens(left)
                    left_idents = TOKEN_RE.findall(left)
                    new_left_indents = []
                    for i, left_ident in enumerate(left_idents):
                        if left_ident in ['->', '[', ']', '.', '{', '}']:
                            continue

                        if left_ident == '(':
                            paren_stack += 1
                        elif left_ident == ')':
                            paren_stack -= 1

                        if left_ident in self.pointer_vars:
                            normalized_var_name = self.pointer_vars.index(left_ident)
                            new_left_indents.append(f'PTR_VAR_{normalized_var_name}')
                        elif left_ident in WRITE_FUNCS or left_ident in USE_FUNCS or left_ident in HEAP_FUNCS:
                            new_left_indents.append(f'FUNC_{left_ident}')
                        elif i < len(left_idents) - 1 and left_idents[i+1] == '(' and str(left_ident).isidentifier():
                            new_left_indents.append(f'FUNC_{left_ident}')
                        elif left_ident in OP_MAP and paren_stack == 0:
                            new_left_indents.append(f'OP_{OP_MAP.get(left_ident)}')
                        elif i > 0 and left_idents[i-1] == '->':
                            new_left_indents.append(f'FIELD_{left_ident}')
                        elif i > 0 and left_idents[i-1] == '[':
                            new_left_indents.append(f'IDX_{left_ident}')
                        elif i < len(left_idents) - 1 and left_idents[i+1] != '(' and str(left_ident).isidentifier() and paren_stack == 0:
                            new_left_indents.append(f'VAR_{left_ident}')
                        elif len(left_idents) == 1:
                            new_left_indents.append(f'VAR_{left_ident}')
                        else:
                            continue

                    left = ' '.join(new_left_indents)

                    # hanlde op
                    op = OP_MAP.get(op)
                    op = f'OP_{op}'
                    
                    # handle right
                    if right in ["0", "'\\0'"]:
                        right = 'CONST_ZERO'
                    elif right == 'NULL':
                        right = 'PTR_NULL'
                    elif right in [str(i) for i in range(1, 9)]:
                        right = f'CONST_{right}'
                    else:
                        right = self._strip_parens(right)
                        right_idents = TOKEN_RE.findall(right)
                        new_right_indents = []
                        for i, right_ident in enumerate(right_idents):
                            if right_ident in ['->', '[', ']', '.', '{', '}']:
                                continue

                            if right_ident == '(':
                                paren_stack += 1
                            elif right_ident == ')':
                                paren_stack -= 1

                            if right_ident in self.pointer_vars:
                                normalized_var_name = self.pointer_vars.index(right_ident)
                                new_right_indents.append(f'PTR_VAR_{normalized_var_name}')
                            elif right_ident in WRITE_FUNCS or right_ident in USE_FUNCS or right_ident in HEAP_FUNCS:
                                new_right_indents.append(f'FUNC_{right_ident}')
                            elif i < len(right_idents) - 1 and right_idents[i+1] == '(' and str(right_ident).isidentifier():
                                new_right_indents.append(f'FUNC_{right_ident}')
                            elif right_ident in OP_MAP and paren_stack == 0:
                                new_right_indents.append(f'OP_{OP_MAP.get(right_ident)}')
                            elif i > 0 and right_idents[i-1] == '->':
                                new_right_indents.append(f'FIELD_{right_ident}')
                            elif i > 0 and right_idents[i-1] == '[':
                                new_right_indents.append(f'IDX_{right_ident}')
                            elif i < len(right_idents) - 1 and right_idents[i+1] != '(' and str(right_ident).isidentifier() and paren_stack == 0:
                                new_right_indents.append(f'VAR_{right_ident}')
                            elif len(right_idents) == 1:
                                new_right_indents.append(f'VAR_{right_ident}')
                            else:
                                continue

                        right = ' '.join(new_right_indents)
                    
                    conds = ' '.join([left, op, right])
                    all_conds.append(conds)
                except:
                    left = self._strip_parens(sub)
                    left_idents = TOKEN_RE.findall(left)
                    new_left_indents = []

                    for i, left_ident in enumerate(left_idents):
                        if left_ident in ['->', '[', ']', '.', '{', '}']:
                            continue

                        if left_ident == '(':
                            paren_stack += 1
                        elif left_ident == ')':
                            paren_stack -= 1

                        if left_ident in self.pointer_vars:
                            normalized_var_name = self.pointer_vars.index(left_ident)
                            new_left_indents.append(f'PTR_VAR_{normalized_var_name}')
                        elif left_ident in WRITE_FUNCS or left_ident in USE_FUNCS or left_ident in HEAP_FUNCS:
                            new_left_indents.append(f'FUNC_{left_ident}')
                        elif i < len(left_idents) - 1 and left_idents[i+1] == '(' and str(left_ident).isidentifier():
                            new_left_indents.append(f'FUNC_{left_ident}')
                        elif left_ident in OP_MAP and paren_stack == 0:
                            new_left_indents.append(f'OP_{OP_MAP.get(left_ident)}')
                        elif i > 0 and left_idents[i-1] == '->':
                            new_left_indents.append(f'FIELD_{left_ident}')
                        elif i > 0 and left_idents[i-1] == '[':
                            new_left_indents.append(f'IDX_{left_ident}')
                        elif i < len(left_idents) - 1 and left_idents[i+1] != '(' and str(left_ident).isidentifier() and paren_stack == 0:
                            new_left_indents.append(f'VAR_{left_ident}')
                        elif len(left_idents) == 1:
                            new_left_indents.append(f'VAR_{left_ident}')
                        else:
                            continue

                    left = ' '.join(new_left_indents)
                    all_conds.append(left)
                
            final_conds = ' '.join(all_conds)
        except:
            final_conds = 'UNKNOWN'

        rand_id = shortuuid.random(length=3)

        self.events.append(
            AbstractEvent(f'LOOP_BEGIN', final_conds, unique_id=rand_id, location=node.start_byte)
        )

        self._visit(body_node)

        self.events.append(
            AbstractEvent(f'LOOP_END', unique_id=rand_id, location=node.start_byte)
        )

        return

#     while_statement
    def _handle_while_statement(self, node):
        condition_node = node.child_by_field_name('condition')
        body_node = node.child_by_field_name('body')

        condition_res = self._extract(condition_node)
        condition = self._strip_parens(condition_res)

        sub_conds = re.split(r'\s*(&&|\|\|)\s*', condition)
        all_conds = []
        for sub in sub_conds:
            sub = sub.strip()
            if sub in ['&&', '||']:
                all_conds.append(f"OP_{OP_MAP.get(sub)}")
                continue

            paren_stack = 0
            try:
                left, op, right = self._split_condition(sub)

                # handle left
                left = self._strip_parens(left)
                left_idents = TOKEN_RE.findall(left)
                new_left_indents = []
                for i, left_ident in enumerate(left_idents):
                    if left_ident in ['->', '[', ']', '.', '{', '}']:
                        continue

                    if left_ident == '(':
                        paren_stack += 1
                    elif left_ident == ')':
                        paren_stack -= 1

                    if left_ident in self.pointer_vars:
                        normalized_var_name = self.pointer_vars.index(left_ident)
                        new_left_indents.append(f'PTR_VAR_{normalized_var_name}')
                    elif left_ident in WRITE_FUNCS or left_ident in USE_FUNCS or left_ident in HEAP_FUNCS:
                        new_left_indents.append(f'FUNC_{left_ident}')
                    elif i < len(left_idents) - 1 and left_idents[i+1] == '(' and str(left_ident).isidentifier():
                        new_left_indents.append(f'FUNC_{left_ident}')
                    elif left_ident in OP_MAP and paren_stack == 0:
                        new_left_indents.append(f'OP_{OP_MAP.get(left_ident)}')
                    elif i > 0 and left_idents[i-1] == '->':
                        new_left_indents.append(f'FIELD_{left_ident}')
                    elif i > 0 and left_idents[i-1] == '[':
                        new_left_indents.append(f'IDX_{left_ident}')
                    elif i < len(left_idents) - 1 and left_idents[i+1] != '(' and str(left_ident).isidentifier() and paren_stack == 0:
                        new_left_indents.append(f'VAR_{left_ident}')
                    elif len(left_idents) == 1:
                        new_left_indents.append(f'VAR_{left_ident}')
                    else:
                        continue

                left = ' '.join(new_left_indents)

                # hanlde op
                op = OP_MAP.get(op)
                op = f'OP_{op}'
                
                # handle right
                if right in ["0", "'\\0'"]:
                    right = 'CONST_ZERO'
                elif right == 'NULL':
                    right = 'PTR_NULL'
                elif right in [str(i) for i in range(1, 9)]:
                    right = f'CONST_{right}'
                else:
                    right = self._strip_parens(right)
                    right_idents = TOKEN_RE.findall(right)
                    new_right_indents = []
                    for i, right_ident in enumerate(right_idents):
                        if right_ident in ['->', '[', ']', '.', '{', '}']:
                            continue

                        if right_ident == '(':
                            paren_stack += 1
                        elif right_ident == ')':
                            paren_stack -= 1

                        if right_ident in self.pointer_vars:
                            normalized_var_name = self.pointer_vars.index(right_ident)
                            new_right_indents.append(f'PTR_VAR_{normalized_var_name}')
                        elif right_ident in WRITE_FUNCS or right_ident in USE_FUNCS or right_ident in HEAP_FUNCS:
                            new_right_indents.append(f'FUNC_{right_ident}')
                        elif i < len(right_idents) - 1 and right_idents[i+1] == '(' and str(right_ident).isidentifier():
                            new_right_indents.append(f'FUNC_{right_ident}')
                        elif right_ident in OP_MAP and paren_stack == 0:
                            new_right_indents.append(f'OP_{OP_MAP.get(right_ident)}')
                        elif i > 0 and right_idents[i-1] == '->':
                            new_right_indents.append(f'FIELD_{right_ident}')
                        elif i > 0 and right_idents[i-1] == '[':
                            new_right_indents.append(f'IDX_{right_ident}')
                        elif i < len(right_idents) - 1 and right_idents[i+1] != '(' and str(right_ident).isidentifier() and paren_stack == 0:
                            new_right_indents.append(f'VAR_{right_ident}')
                        elif len(right_idents) == 1:
                            new_right_indents.append(f'VAR_{right_ident}')
                        else:
                            continue

                    right = ' '.join(new_right_indents)
                
                conds = ' '.join([left, op, right])
                all_conds.append(conds)
            except:
                left = self._strip_parens(sub)
                left_idents = TOKEN_RE.findall(left)
                new_left_indents = []

                for i, left_ident in enumerate(left_idents):
                    if left_ident in ['->', '[', ']', '.', '{', '}']:
                        continue

                    if left_ident == '(':
                        paren_stack += 1
                    elif left_ident == ')':
                        paren_stack -= 1

                    if left_ident in self.pointer_vars:
                        normalized_var_name = self.pointer_vars.index(left_ident)
                        new_left_indents.append(f'PTR_VAR_{normalized_var_name}')
                    elif left_ident in WRITE_FUNCS or left_ident in USE_FUNCS or left_ident in HEAP_FUNCS:
                        new_left_indents.append(f'FUNC_{left_ident}')
                    elif i < len(left_idents) - 1 and left_idents[i+1] == '(' and str(left_ident).isidentifier():
                        new_left_indents.append(f'FUNC_{left_ident}')
                    elif left_ident in OP_MAP and paren_stack == 0:
                        new_left_indents.append(f'OP_{OP_MAP.get(left_ident)}')
                    elif i > 0 and left_idents[i-1] == '->':
                        new_left_indents.append(f'FIELD_{left_ident}')
                    elif i > 0 and left_idents[i-1] == '[':
                        new_left_indents.append(f'IDX_{left_ident}')
                    elif i < len(left_idents) - 1 and left_idents[i+1] != '(' and str(left_ident).isidentifier() and paren_stack == 0:
                        new_left_indents.append(f'VAR_{left_ident}')
                    elif len(left_idents) == 1:
                        new_left_indents.append(f'VAR_{left_ident}')
                    else:
                        continue

                left = ' '.join(new_left_indents)
                all_conds.append(left)
            
        final_conds = ' '.join(all_conds)

        rand_id = shortuuid.random(length=3)

        self.events.append(
            AbstractEvent(f'LOOP_BEGIN', final_conds, unique_id=rand_id, location=node.start_byte)
        )

        self._visit(body_node)

        self.events.append(
            AbstractEvent(f'LOOP_END', unique_id=rand_id, location=node.start_byte)
        )

        return

#     return_statement

#     break_statement

#     continue_statement

# #    ========== Expressions ==========

#     call_expression
    def _handle_call_expression(self, node):
        fn_name_node = node.child_by_field_name('function')
        args = node.child_by_field_name('arguments')

        fn_name = self._extract(fn_name_node)
        
        args_list = []
        for c in args.named_children:
            result = self._visit(c)
            args_list.append(result)

        if fn_name in WRITE_FUNCS:
            spec = WRITE_FUNCS[fn_name]

            buff = 'UNKNOWN'
            
            for i in range(spec['buf'], len(args_list)):
                if i != spec['buf'] and fn_name not in ['scanf', 'sscanf', 'fscanf', 'recvmsg']:
                    continue
                
                if spec['buf'] < len(args_list):
                    try:
                        try:
                            buff = args_list[i].get('var_name')
                            normalized_var_name = self.pointer_vars.index(buff)
                            buff = f'PTR_VAR_{normalized_var_name}'
                        except:
                            if isinstance(args_list[i], tuple):
                                result = args_list[i]
                                buf_list = self._flatten_binary_expr(result)

                                list_buff = []
                                for r in buf_list:
                                    if isinstance(r, dict):
                                        if 'var_name' in r:
                                            buff = r.get('var_name')

                                            try:
                                                normalized_var_name = self.pointer_vars.index(buff)
                                                buff = f'PTR_VAR_{normalized_var_name}'
                                            except:
                                                buff = buff

                                            list_buff.append(buff)
                                        elif 'fn_name' in r:
                                            fn_name = r.get('fn_name')
                                            args = r.get('args')
                                            
                                            args_list = []
                                            for arg in args:
                                                if isinstance(arg, dict):
                                                    buff = arg.get('var_name')
                                                    
                                                    try:
                                                        normalized_var_name = self.pointer_vars.index(buff)
                                                        buff = f'PTR_VAR_{normalized_var_name}'
                                                    except:
                                                        buff = buff

                                                    list_buff.append(buff)
                                                elif isinstance(arg, tuple):
                                                    flatten = self._flatten_binary_expr(arg)
                                                    list_arg = []
                                                    for r in flatten:
                                                        if isinstance(r, dict):
                                                            list_arg.append(r.get('var_name'))
                                                        elif isinstance(r, str):
                                                            list_arg.append(r)

                                                    arg_name = ''.join(list_arg)
                                                    splitted = re.split(r'(\+|-(?!>)|\*|/)', arg_name)
                                                    args_list.append(' '.join(splitted))

                                            args = ', '.join(args_list)
                                            list_buff.append(f'{fn_name}({args})')
                                    elif isinstance(r, str):
                                        buff = r

                                        if buff in self.pointer_vars:
                                            normalized_var_name = self.pointer_vars.index(buff)
                                            buff = f'PTR_VAR_{normalized_var_name}'
                                        elif buff in OP_MAP:
                                            buff = f'OP_{OP_MAP.get(r)}'

                                        list_buff.append(buff)
                                    elif isinstance(r, list):
                                        for sub_r in r:
                                            list_buff.append(sub_r)

                                # buff_name = ''.join(list_buff)
                                # splitted = re.split(r'(\+|-(?!>)|\*|/)', buff_name)
                                # buff = ' '.join(splitted)
                                buff = ' '.join(list_buff)
                            else:
                                try:
                                    buff = args_list[i].get('var_name')
                                    if '->' in buff:
                                        split_name = buff.split('->', 1)
                                    elif '.' in buff:
                                        split_name = buff.split('.', 1)
                                    else:
                                        split_name = buff.split('->', 1)

                                    if split_name[0] not in self.pointer_vars:
                                        continue

                                    buff_list = []
                                    for i, vn in enumerate(split_name):
                                        if i == 0:
                                            normalized_var_name = self.pointer_vars.index(vn)
                                            buff_list.append(f'PTR_VAR_{normalized_var_name}')
                                        else:
                                            buff_list.append(f'FIELD_{vn}')
                                    
                                    buff = ' '.join(buff_list)

                                except:
                                    buff = args_list[i]
                                
                                    if buff not in self.pointer_vars:
                                        continue
                    except:
                        result = args_list[i]
                        buff_list = self._flatten_field_chain(result)
                        buff = '->'.join(buff_list)
                
                if buff is None:
                    continue

                abs_size = SizeExpr(
                    kind='UNKNOWN',
                    value=None
                )

                if spec['size'] is not None and spec['size'] < len(args_list):
                    try:
                        try:
                            size = args_list[spec['size']].get('var_name')
                        except:
                            if isinstance(args_list[spec['size']], tuple):
                                result = args_list[spec['size']]
                                size_list = self._flatten_binary_expr(result)

                                list_size = []
                                for r in size_list:
                                    if isinstance(r, dict):
                                        if 'var_name' in r:
                                            list_size.append(r.get('var_name'))
                                        elif 'fn_name' in r:
                                            fn_name = r.get('fn_name')
                                            args = r.get('args')
                                            
                                            args_list = []
                                            for arg in args:
                                                if isinstance(arg, dict):
                                                    args_list.append(arg.get('var_name'))
                                                elif isinstance(arg, tuple):
                                                    flatten = self._flatten_binary_expr(arg)
                                                    list_arg = []
                                                    for r in flatten:
                                                        if isinstance(r, dict):
                                                            list_arg.append(r.get('var_name'))
                                                        elif isinstance(r, str):
                                                            list_arg.append(r)

                                                    arg_name = ''.join(list_arg)
                                                    splitted = re.split(r'(\+|-(?!>)|\*|/)', arg_name)
                                                    args_list.append(' '.join(splitted))

                                            args = ', '.join(args_list)
                                            list_size.append(f'{fn_name}({args})')
                                    elif isinstance(r, str):
                                        list_size.append(r)
                                    elif isinstance(r, list):
                                        for sub_r in r:
                                            list_size.append(sub_r)

                                size_name = ''.join(list_size)
                                splitted = re.split(r'(\+|-(?!>)|\*|/)', size_name)
                                size = ' '.join(splitted)
                            else:
                                size = args_list[spec['size']]
                    except:
                        result = args_list[spec['size']]
                        size_list = self._flatten_field_chain(result)
                        size = '->'.join(size_list)
                    
                    abs_size = SizeExpr(
                        kind='CONST',
                        value=size
                    )

                self.events.append(
                    AbstractEvent(
                        kind=f'WRITE_{fn_name.upper()}',
                        buffer=buff,
                        size=abs_size,
                        location=node.start_byte
                    )
                )
         
        return {
            'fn_name': fn_name,
            'args': args_list
        }

#     assignment_expression
    def _handle_assignment_expression(self, node):
        left = node.child_by_field_name('left')
        operator = node.child_by_field_name('operator')
        right = node.child_by_field_name('right')

        left_res = self._visit(left)
        op_res = self._extract(operator)
        right_res = self._visit(right)
        
        if not left_res or not right_res:
            return
        
        if left.type == 'identifier':
            if right.type == 'field_expression' and op_res == '=':
                var_name = left_res.get('var_name')
                
                if var_name in self.pointer_vars:
                    result = right_res
                    src_list = self._flatten_field_chain(result)
                    new_src = '->'.join(src_list)
                    self._update_region_source(var_name, None, new_src)
            
            if right.type == 'identifier':
                var_name = left_res.get('var_name')
                
                if var_name in self.pointer_vars:
                    src_name = right_res.get('var_name')
                    self._update_region_source(var_name, None, src_name)
            
            if right.type == 'binary_expression':
                var_name = left_res.get('var_name')
                
                if var_name in self.pointer_vars:
                    result = self._flatten_binary_expr(right_res)
                    
                    list_src = []
                    for r in result:
                        if isinstance(r, dict):
                            if 'var_name' in r:
                                list_src.append(r.get('var_name'))
                            elif 'fn_name' in r:
                                fn_name = r.get('fn_name')
                                args = r.get('args')
                                
                                args_list = []
                                for arg in args:
                                    if isinstance(arg, dict):
                                        args_list.append(arg.get('var_name'))
                                    elif isinstance(arg, tuple):
                                        flatten = self._flatten_binary_expr(arg)
                                        list_arg = []
                                        for r in flatten:
                                            if isinstance(r, dict):
                                                list_arg.append(r.get('var_name'))
                                            elif isinstance(r, str):
                                                list_arg.append(r)

                                        arg_name = ''.join(list_arg)
                                        splitted = re.split(r'(\+|-(?!>)|\*|/)', arg_name)
                                        args_list.append(' '.join(splitted))

                                args = ', '.join(args_list)
                                list_src.append(f'{fn_name}({args})')
                        elif isinstance(r, str):
                            list_src.append(r)
                        elif isinstance(r, list):
                            for sub_r in r:
                                list_src.append(sub_r)
                    
                    src_name = ''.join(list_src)
                    splitted = re.split(r'(\+|-(?!>)|\*|/)', src_name)
                    src_name = ' '.join(splitted)
                    self._update_region_source(var_name, None, src_name)
            
            if right.type == 'call_expression':
                var_name = left_res.get('var_name')
                fn_name = right_res.get('fn_name')
                fn_args = right_res.get('args')

                if var_name in self.pointer_vars and fn_name in HEAP_FUNCS:
                    size = self._extract_alloc_size(fn_name, fn_args)
                    size_list = self._flatten_binary_expr(size.value)

                    list_size = []
                    for r in size_list:
                        if isinstance(r, dict):
                            list_size.append(r.get('var_name'))
                        elif isinstance(r, str):
                            list_size.append(r)

                    size_name = ''.join(list_size)
                    splitted = re.split(r'(\+|-(?!>)|\*|/)', size_name)
                    size_fin = ' '.join(splitted)
                
                    self._update_region_source(var_name, size_fin, 'HEAP')
                    
                    try:
                        var_type = self.variable_data_type[var_name]
                        fields = self.struct_fields[var_type]
                    except KeyError:
                        fields = None

                    if fields:
                        for field_name, field_size in fields:
                            self.events.append(
                                AbstractEvent(
                                    kind='ALLOC',
                                    buffer=f'{var_name}.{field_name}',
                                    size=SizeExpr(
                                        kind='CONST',
                                        value=field_size
                                    ),
                                    location=node.start_byte
                                )
                            )
                    else:
                        self.events.append(
                                AbstractEvent(
                                    kind='ALLOC',
                                    buffer=var_name,
                                    size=SizeExpr(
                                        kind='CONST',
                                        value=size_fin
                                    ),
                                    location=node.start_byte
                                )
                            )
                    
            
            if right.type == 'cast_expression':
                var_name = left_res.get('var_name')
                if var_name in self.pointer_vars:
                    result = self._flatten_binary_expr(right_res)

                    list_src = []
                    for r in result:
                        if isinstance(r, dict):
                            if 'var_name' in r:
                                list_src.append(r.get('var_name'))
                            elif 'fn_name' in r:
                                fn_name = r.get('fn_name')
                                args = r.get('args')
                                
                                args_list = []
                                for arg in args:
                                    if isinstance(arg, dict):
                                        args_list.append(arg.get('var_name'))
                                    elif isinstance(arg, tuple):
                                        flatten = self._flatten_binary_expr(arg)
                                        list_arg = []
                                        for r in flatten:
                                            if isinstance(r, dict):
                                                list_arg.append(r.get('var_name'))
                                            elif isinstance(r, str):
                                                list_arg.append(r)

                                        arg_name = ''.join(list_arg)
                                        splitted = re.split(r'(\+|-(?!>)|\*|/)', arg_name)
                                        args_list.append(' '.join(splitted))

                                args = ', '.join(args_list)
                                list_src.append(f'{fn_name}({args})')
                        elif isinstance(r, str):
                            list_src.append(r)
                        elif isinstance(r, list):
                            for sub_r in r:
                                list_src.append(sub_r)

                    src_name = ''.join(list_src)
                    splitted = re.split(r'(\+|-(?!>)|\*|/)', src_name)
                    src_name = ' '.join(splitted)
                    self._update_region_source(var_name, None, src_name)

        if left.type == 'pointer_expression':
            result = self._flatten_binary_expr(left_res)
            
            list_src = []
            for r in result:
                if isinstance(r, dict):
                    if 'var_name' in r:
                        list_src.append(r.get('var_name'))
                    elif 'fn_name' in r:
                        fn_name = r.get('fn_name')
                        args = r.get('args')

                        args_list = []
                        for arg in args:
                            if isinstance(arg, dict):
                                args_list.append(arg.get('var_name'))
                            elif isinstance(arg, tuple):
                                flatten = self._flatten_binary_expr(arg)
                                list_arg = []
                                for r in flatten:
                                    if isinstance(r, dict):
                                        list_arg.append(r.get('var_name'))
                                    elif isinstance(r, str):
                                        list_arg.append(r)

                                arg_name = ''.join(list_arg)
                                splitted = re.split(r'(\+|-(?!>)|\*|/)', arg_name)
                                args_list.append(' '.join(splitted))

                        args = ', '.join(args_list)
                        list_src.append(f'{fn_name}({args})')
                elif isinstance(r, str):
                    list_src.append(r)
                elif isinstance(r, list):
                    for sub_r in r:
                        list_src.append(sub_r)
            
            src_name = ''.join(list_src)
            splitted = re.split(r'(\+|-(?!>)|\*|/)', src_name)
            var_name_list = splitted

            if var_name_list[0] not in self.pointer_vars:
                return

            i = 0
            while i < len(var_name_list):
                if i == 0:
                    normalized_var_name = self.pointer_vars.index(var_name_list[i])
                    var_name_list[i] = f'PTR_VAR_{normalized_var_name}'
                    i += 1
                elif var_name_list[i] == '+':
                    var_name_list[i] = f"OP_{OP_MAP.get(var_name_list[i])}"
                    var_name_list[i+1] = f'IDX_{var_name_list[i+1]}'
                    i += 2
                else:
                    var_name_list[i] = f'FIELD_{var_name_list[i]}'
                    i += 1

            var_name = ' '.join(var_name_list)

            self.events.append(
                AbstractEvent(
                    kind='PTR_WRITE',
                    buffer=var_name,
                    location=node.start_byte
                )
            )

        if left.type == 'field_expression':
            if right.type == 'call_expression':
                var_name_list = self._flatten_field_chain(left_res)

                var_name = '->'.join(var_name_list)
                fn_name = right_res.get('fn_name')
                fn_args = right_res.get('args')

                if var_name in self.pointer_vars and fn_name in HEAP_FUNCS:
                    size = self._extract_alloc_size(fn_name, fn_args)
                    self._update_region_source(var_name, size, 'HEAP')

                    var_type = self.variable_data_type[var_name]

                    try:
                        fields = self.struct_fields[var_type]
                    except KeyError:
                        return
                    
                    for field_name, field_size in fields:
                        self.events.append(
                            AbstractEvent(
                                kind='ALLOC',
                                buffer=f'{var_name}.{field_name}',
                                size=SizeExpr(
                                    kind='CONST',
                                    value=field_size
                                ),
                                location=node.start_byte
                            )
                        )

        if left.type == 'subscript_expression':
            if right.type in ['char_literal', 'number_literal']:
                indexs = left_res.get('index')

                if isinstance(indexs, tuple):
                    if '.' in indexs or '->' in indexs:
                        index_list = []
                        for index in indexs:
                            if isinstance(index, dict):
                                index_list.append(index.get('var_name'))
                            else:
                                index_list.append(index)
                        
                        index = SizeExpr(
                            kind='IDX',
                            value=''.join(index_list)
                        )
                    else:
                        result = self._flatten_binary_expr(indexs)

                        list_index = []
                        for r in result:
                            if isinstance(r, dict):
                                if 'var_name' in r:
                                    list_index.append(r.get('var_name'))
                                elif 'fn_name' in r:
                                    fn_name = r.get('fn_name')
                                    args = r.get('args')
                                    
                                    args_list = []
                                    for arg in args:
                                        if isinstance(arg, dict):
                                            args_list.append(arg.get('var_name'))
                                        elif isinstance(arg, tuple):
                                            flatten = self._flatten_binary_expr(arg)
                                            list_arg = []
                                            for r in flatten:
                                                if isinstance(r, dict):
                                                    list_arg.append(r.get('var_name'))
                                                elif isinstance(r, str):
                                                    list_arg.append(r)

                                            arg_name = ''.join(list_arg)
                                            splitted = re.split(r'(\+|-(?!>)|\*|/)', arg_name)
                                            args_list.append(' '.join(splitted))

                                    args = ', '.join(args_list)
                                    list_index.append(f'{fn_name}({args})')
                            elif isinstance(r, str):
                                list_index.append(r)
                            elif isinstance(r, list):
                                for sub_r in r:
                                    list_index.append(sub_r)

                        index_name = ''.join(list_index)
                        splitted = re.split(r'(\+|-(?!>)|\*|/)', index_name)
                        index_name = ' '.join(splitted)
                        size = index_name

                        index = SizeExpr(
                            kind='IDX',
                            value=size
                        )
                else:
                    index = SizeExpr(
                        kind='IDX',
                        value=indexs
                    )

                try:
                    normalized_var_name = self.pointer_vars.index(left_res.get('var_name'))
                    self.events.append(
                        AbstractEvent(
                            kind='WRITE_INDEX',
                            buffer=f'PTR_VAR_{normalized_var_name}',
                            size=index,
                            location=node.start_byte
                        )
                    )
                except:
                    buff_name = left_res.get('var_name')

                    if '->' in buff_name:
                        split_name = buff_name.split('->', 1)
                    elif '.' in buff_name:
                        split_name = buff_name.split('.', 1)
                    else:
                        split_name = buff_name.split('->', 1)

                    if split_name[0] not in self.pointer_vars:
                        return

                    normalized_var_name = self.pointer_vars.index(split_name[0])
                    self.events.append(
                        AbstractEvent(
                            kind='WRITE_INDEX',
                            buffer=f'PTR_VAR_{normalized_var_name} FIELD_{split_name[1]}',
                            size=index,
                            location=node.start_byte
                        )
                    )
                return

#     binary_expression
    def _handle_binary_expression(self, node):
        left_node = node.child_by_field_name('left')
        op = node.child_by_field_name('operator')
        right_node = node.child_by_field_name('right')

        left = self._visit(left_node)
        op = self._extract(op)
        right = self._visit(right_node)

        if left_node.type == 'identifier':
            left = left.get('var_name')
        if right_node.type == 'identifier':
            right = right.get('var_name')

        return (left, op, right)

#     unary_expression

#     pointer_expression
    def _handle_pointer_expression(self, node):
        left_node = node.child_by_field_name('argument')
        return self._visit(left_node)

#     update_expression
    def _handle_update_expression(self, node):
        argument_node = node.child_by_field_name('argument')
        argument_res = self._visit(argument_node)
        
        argument_res = self._flatten_field_chain(argument_res)

        if len(argument_res) == 0:
            return argument_res
        
        base_ptr = argument_res[0]

        if base_ptr not in self.pointer_vars:
            return

        var_name_list = []
        for i, vn in enumerate(argument_res):
            if i == 0:
                normalized_var_name = self.pointer_vars.index(argument_res[i])
                var_name_list.append(f'PTR_VAR_{normalized_var_name}')
            else:
                var_name_list.append(f'FIELD_{vn}')

        var_name = ' '.join(var_name_list)

        rand_id = shortuuid.random(length=3)
        if base_ptr in self.pointer_vars:
            self.events.append(
                AbstractEvent(
                    kind='PTR_ADVANCE',
                    buffer=var_name,
                    # unique_id=rand_id,
                    location=node.start_byte
                )
            )
        return argument_res

#     subscript_expression
    def _handle_subscript_expression(self, node):
        var_name_node = node.child_by_field_name('argument')
        index_node = node.child_by_field_name('index')

        result = self._visit(var_name_node)
        index = self._visit(index_node)

        if index_node.type == 'identifier':
            index = index.get('var_name')

        if isinstance(result, tuple):
            list_buff = []
            for r in result:
                if isinstance(r, dict):
                    if 'var_name' in r:
                        list_buff.append(r.get('var_name'))
                    elif 'fn_name' in r:
                        fn_name = r.get('fn_name')
                        args = r.get('args')
                        
                        args_list = []
                        for arg in args:
                            if isinstance(arg, dict):
                                args_list.append(arg.get('var_name'))
                            elif isinstance(arg, tuple):
                                flatten = self._flatten_binary_expr(arg)
                                list_arg = []
                                for r in flatten:
                                    if isinstance(r, dict):
                                        list_arg.append(r.get('var_name'))
                                    elif isinstance(r, str):
                                        list_arg.append(r)

                                arg_name = ''.join(list_arg)
                                splitted = re.split(r'(\+|-(?!>)|\*|/)', arg_name)
                                args_list.append(' '.join(splitted))

                        args = ', '.join(args_list)
                        list_buff.append(f'{fn_name}({args})')
                elif isinstance(r, str):
                    list_buff.append(r)
                elif isinstance(r, list):
                    for sub_r in r:
                        list_buff.append(sub_r)

            buff_name = ''.join(list_buff)
            splitted = re.split(r'(\+|-(?!>)|\*|/)', buff_name)
            var_name = ' '.join(splitted)
        else:
            var_name_list = self._flatten_field_chain(result)
            var_name = '->'.join(var_name_list)
        
        return {
            'var_name': var_name,
            'index': index
        }

#     field_expression
    def _handle_field_expression(self, node):
        var_name_node = node.child_by_field_name('argument')
        operator_node = node.child_by_field_name('operator')
        field_name_node = node.child_by_field_name('field')

        var_name = self._visit(var_name_node)
        op = self._extract(operator_node)
        field_name = self._visit(field_name_node)
        # print(var_name)
        return (var_name, op, field_name)
    
#     parenthesized_expression
    def _handle_parenthesized_expression(self, node):
        for c in node.named_children:
            if c.type == 'identifier':
                return self._visit(c)
            if c.type == 'binary_expression':
                return self._visit(c)
            if c.type == 'update_expression':
                return self._visit(c)
            if c.type == 'field_expression':
                return self._visit(c)
            if c.type == 'cast_expression':
                return self._visit(c)
            if c.type == 'pointer_expression':
                return self._visit(c)
            
#     conditional_expression

#     cast_expression
    def _handle_cast_expression(self, node):
        for c in node.named_children:
            if c.type == 'type_descriptor':
                self._visit(c)
            if c.type == 'identifier':
                return self._visit(c)
            if c.type == 'call_expression':
                return self._visit(c)
            if c.type == 'parenthesized_expression':
                return self._visit(c)
            if c.type == 'pointer_expression':
                return self._visit(c)
            if c.type == 'field_expression':
                return self._visit(c)

#     sizeof_expression
    def _handle_sizeof_expression(self, node):
        return self._extract(node)

# #    ========== Literals ==========

#     number_literal
    def _handle_number_literal(self, node):
        val = self._extract(node)
        return val.strip()

#     string_literal
    def _handle_string_literal(self, node):
        val = self._extract(node)
        return val.strip()

#     char_literal
    def _handle_char_literal(self, node):
        val = self._extract(node)
        return val.strip()
    
# #    ========== Type Descriptor ==========
    def _handle_type_descriptor(self, node):
        node_type = node.child_by_field_name('type')
        return self._visit(node_type)


    # ===== END OF HANDLERS =====

    def _extract(self, node):
        return utils.node_text(node, code=self.code)

    def _split_condition(self, cond):
        parts = re.split(r'(?<!-)(<=|>=|==|!=|<|>)', cond)
        if len(parts) != 3:
            return None, None
        left, op, right = parts
        return left.strip(), op.strip(), right.strip()

    def _split_logical_conditions(self, text):
        return re.split(r'\s*&&\s*|\s*\|\|\s*', text)
    
    def _strip_parens(self, text: str) -> str:
        text = text.strip()
        if text.startswith('(') and text.endswith(')'):
            return text[1:-1].strip()
        return text
    
    def _is_pointer(self, node):
        name = self._extract(node, self.code)
        return name in self.pointer_vars
    
    def _update_region_source(self, buf, size, source):
        for e in reversed(self.events):
            if e.kind == 'REGION' and e.buffer == buf:
                e.source = source
                e.size = size or SizeExpr('UNKNOWN', None)
                return

        # fallback (should rarely happen)
        # self.events.append(
        #     AbstractEvent(
        #         kind='REGION',
        #         buffer=buf,
        #         size=size or SizeExpr('UNKNOWN', None),
        #         source=source,
        #     )
        # )

    def _extract_alloc_size(self, fn_name, args):
        if fn_name == 'malloc':
            # malloc(size)
            if len(args) >= 1:
                return SizeExpr(
                    kind='CONST',
                    value=args[0]
                )

        elif fn_name == 'calloc':
            # calloc(nmemb, size)
            if len(args) >= 2:
                return SizeExpr(
                    kind='EXPR',
                    value=(args[0], '*', args[1])
                )

        elif fn_name == 'realloc':
            # realloc(ptr, size)
            if len(args) >= 2:
                return SizeExpr(
                    kind='CONST',
                    value=args[1]
                )

        return SizeExpr('UNKNOWN', None)
        
    def _alphanum(self, str):
        return re.sub(r'[^a-zA-Z0-9]', '', str)
    
    def _flatten_field_chain(self, expr):
        chain = []

        def walk(node):
            if isinstance(node, tuple) and len(node) == 3:
                left, op, right = node

                if op == '->' or op == '.' or op in ['+', '-', '*', '/']:
                    walk(left)
                    walk(right)
                    return
            if isinstance(node, dict):
                chain.append(node['var_name'])
            if isinstance(node, list):
                for n in node:
                    chain.append(n)
        walk(expr)

        return chain
    
    def _flatten_mixed_expr(self, expr, out=None):
        if out is None:
            out = []

        # Recursive binary expression
        if isinstance(expr, tuple) and len(expr) == 3:
            left, op, right = expr

            if op in ('&&', '||'):
                self._flatten_mixed_expr(left, out)
                self._flatten_mixed_expr(right, out)
            else:
                # atomic constraint like (numSamples <= 0)
                out.append(expr)

            return out

        # Dict leaf (identifier, field, etc.)
        if isinstance(expr, dict):
            out.append(expr['var_name'])
            return out

        # String / number leaf
        out.append(expr)
        return out
    
    def _flatten_binary_expr(self, expr, out=None):
        if out is None:
            out = []

        if isinstance(expr, tuple) and len(expr) == 3:
            left, op, right = expr
            self._flatten_binary_expr(left, out)
            out.append(op)
            self._flatten_binary_expr(right, out)
            return out

        out.append(expr)
        return out

    
    def _dump(self, q=0):
        # self.normalize()
        for e in self.events:
            print(str(e))
        if q == 1:
            exit()


    def save(self, name):
        with open(f'{name}.air', 'w', encoding='utf-8') as f:
            for event in self.events:
                f.write(str(event) + '\n')

    def normalize(self):
        seen = set()
        unique = []

        for e in self.events:
            key = (e.kind, e.buffer, str(e.size), e.unique_id)

            if key not in seen:
                seen.add(key)
                unique.append(e)
        
        i = 0
        result = []
        while i < len(unique):
            if unique[i].kind == 'LOOP_BEGIN' and i + 1 < len(unique) and unique[i+1].kind == 'LOOP_END':
                i += 2
            else:
                result.append(unique[i])
                i += 1

        self.events = result

    def get_gcb_input(self):
        tokens = []
        event_spans = []

        def tokenize(ev: AbstractEvent):
            token = [ev.kind]

            if ev.buffer:
                token += ev.buffer.replace('->', ' -> ').split()

            if ev.size:
                token += str(ev.size).replace('(', ' ').replace(')', ' ').split()

            if ev.source:
                token.append(ev.source)

            return token
        
        for ev in self.events:
            start = len(tokens)
            toks = tokenize(ev)
            tokens.extend(toks)
            end = len(tokens)
            event_spans.append((start, end))

        # ---- Phase 2: build event-level DFG ----
        dfg_event = defaultdict(set)

        last_region = {}
        last_size = {}
        last_ptr = {}
        last_constraint = {}
        loop_stack = []

        for idx, ev in enumerate(self.events):

            if ev.kind == 'REGION':
                last_region[ev.buffer] = idx

                base_source = ev.source.replace('->', ' -> ').replace('.', ' ').split()[0]
                if base_source in last_region:
                    dfg_event[idx].add(last_region[base_source])

            elif ev.kind == 'ALLOC':
                base = ev.buffer.replace('->', ' -> ').replace('.', ' ').split()[0]
                if ev.buffer in last_size:
                    dfg_event[idx].add(last_size[ev.buffer])
                last_region[base] = idx

            elif ev.kind == 'SIZE':
                if ev.buffer in last_region:
                    dfg_event[idx].add(last_region[ev.buffer])
                last_size[ev.buffer] = idx

            elif str(ev.kind).startswith('WRITE_'):
                base = ev.buffer.replace('->', ' -> ').replace('.', ' ').split()[0]

                if ev.size:
                    val = str(ev.size.value).split()
                else:
                    val = None
    
                if val:
                    for v in val:
                        if v in last_constraint:
                            dfg_event[idx].add(last_constraint[v])
                # if ev.size and ev.size.value in last_constraint:
                #     dfg_event[idx].add(last_constraint[ev.size.value])

                if base in last_region:
                    dfg_event[idx].add(last_region[base])

                if base in last_size:
                    dfg_event[idx].add(last_size[base])

                if loop_stack:
                    for i, var in reversed(loop_stack):
                        if var in val:
                            dfg_event[idx].add(i)
                    # dfg_event[idx].add(loop_stack[-1])

                if base in last_ptr:
                    dfg_event[idx].add(last_ptr[base])

            elif ev.kind == 'PTR_WRITE':
                if ev.buffer in last_region:
                    dfg_event[idx].add(last_region[ev.buffer])

                if loop_stack:
                    for i, _ in reversed(loop_stack):
                        dfg_event[idx].add(i)

                # last_ptr[ev.buffer] = idx

            elif ev.kind == 'PTR_ADVANCE':
                if ev.buffer in last_region:
                    dfg_event[idx].add(last_region[ev.buffer])

                if ev.buffer in last_ptr:
                    dfg_event[idx].add(last_ptr[ev.buffer])

                if loop_stack:
                    for i, _ in reversed(loop_stack):
                        dfg_event[idx].add(i)

                last_ptr[ev.buffer] = idx

            elif ev.kind == 'CONSTRAINT':
                last_constraint[ev.size.value[0]] = idx

            elif ev.kind == 'LOOP_BEGIN':
                val = self._alphanum(ev.buffer)
                if val in last_constraint:
                    dfg_event[idx].add(last_constraint[val])
                    
                # loop_stack.append(idx)
                loop_stack.append((idx, val))

            elif ev.kind == 'LOOP_END':
                loop_stack.pop()

        # print(last_region)

        # ---- Phase 3: convert to GraphCodeBERT DFG ----
        dfg = []
        for dst_event, src_events in dfg_event.items():
            dst_start, dst_end = event_spans[dst_event]
            ev = self.events[dst_event]

            dst_token = dst_start

            src_tokens = []
            for src_event in src_events:
                src_start, _ = event_spans[src_event]
                src_tokens.append(src_start)

            dfg.append((
                ev.buffer or ev.kind,
                dst_token,
                src_tokens
            ))

        return {
            'tokens': tokens,
            'dfg': dfg
        }
    
    # def truncate(self, max_budget=120):
    #     def event_cost(ev):
    #         """
    #         Approximate token cost of an AbstractEvent.
    #         This correlates well with subword explosion.
    #         """
    #         cost = 1

    #         if getattr(ev, 'buffer', None):
    #             cost += len(ev.buffer.replace('->', ' ').replace('.', ' ').split())

    #         if getattr(ev, 'size', None):
    #             cost += len(str(ev.size).split())

    #         return cost
        
    #     def rebalance_loops(events):
    #         """
    #         Ensure LOOP_BEGIN / LOOP_END are balanced.
    #         Drop unmatched LOOP_END and trailing LOOP_BEGIN.
    #         """
    #         stack = []
    #         result = []

    #         for ev in events:
    #             if ev.kind == 'LOOP_BEGIN':
    #                 stack.append(ev)
    #                 result.append(ev)

    #             elif ev.kind == 'LOOP_END':
    #                 if stack:
    #                     stack.pop()
    #                     result.append(ev)
    #                 # else: unmatched LOOP_END → drop

    #             else:
    #                 result.append(ev)

    #         # Drop unmatched LOOP_BEGIN (from the end)
    #         while stack:
    #             lb = stack.pop()
    #             if lb in result:
    #                 result.remove(lb)

    #         return result
        
    #     budget = max_budget
    #     keep = [False] * len(self.events)

    #     # 1️⃣ Always keep REGION / ALLOC
    #     for i, ev in enumerate(self.events):
    #         if ev.kind in ('REGION', 'ALLOC', 'WRITE', 'PTR_WRITE'):
    #             keep[i] = True
    #             budget -= event_cost(ev)

    #     if budget <= 0:
    #         result = rebalance_loops([e for i, e in enumerate(self.events) if keep[i]])
    #         self.events = result

    #     # 2️⃣ Walk self.events IN ORDER, keep if budget allows
    #     for i, ev in enumerate(self.events):
    #         if keep[i]:
    #             continue

    #         cost = event_cost(ev)
    #         priority = EVENT_PRIORITY.get(ev.kind, 0)

    #         # low-priority self.events are skippable
    #         if priority < 50 and budget - cost < 0:
    #             continue

    #         if budget - cost < 0:
    #             continue

    #         keep[i] = True
    #         budget -= cost

    #     # 3️⃣ Build truncated list (order preserved)
    #     truncated = [ev for i, ev in enumerate(self.events) if keep[i]]

    #     # 4️⃣ Fix loops (balance + containment)
    #     truncated = rebalance_loops(truncated)

    #     self.events = truncated

    def truncate(self, budget=50):
        seen = set()
        last_ptr = set()
        keep = [False] * len(self.events)
        loop_stack = []

        # First pass: identify written pointers
        for ev in self.events:
            if ev.kind in ('PTR_WRITE', 'PTR_ADVANCE') or str(ev.kind).startswith('WRITE_'):
                last_ptr.add(ev.buffer)

        # Second pass: mark keep + control closure
        for i, ev in enumerate(self.events):

            if ev.kind == 'LOOP_BEGIN':
                loop_stack.append(i)
                continue

            if ev.kind == 'LOOP_END':
                if loop_stack:
                    loop_stack.pop()
                continue

            if ev.kind in ('PTR_WRITE', 'PTR_ADVANCE') or str(ev.kind).startswith('WRITE_'):
                # if ev.buffer not in seen:
                #     keep[i] = True
                #     seen.add(ev.buffer)
                keep[i] = True

                # 🔑 control-dependence: keep all enclosing loops
                for lb_idx in loop_stack:
                    keep[lb_idx] = True

            if ev.kind in ('REGION', 'ALLOC'):
                if ev.buffer in last_ptr:
                    keep[i] = True

        # Third pass: keep LOOP_END matching kept LOOP_BEGIN
        stack = []
        for i, ev in enumerate(self.events):
            if ev.kind == 'LOOP_BEGIN' and keep[i]:
                stack.append(i)
            elif ev.kind == 'LOOP_END' and stack:
                stack.pop()
                keep[i] = True

        def event_cost(ev):
            cost = 1

            if getattr(ev, 'buffer', None):
                cost += len(ev.buffer.replace('->', ' ').replace('.', ' ').split())

            if getattr(ev, 'size', None):
                cost += len(str(ev.size).split())

            return cost
    
        for i, ev in enumerate(self.events):
            if ev.kind == 'CONSTRAINT':
                cost = event_cost(ev)
                if budget - cost < 0:
                    continue

                budget -= cost
                keep[i] = True

        # Final truncation
        self.events = [ev for i, ev in enumerate(self.events) if keep[i]]
