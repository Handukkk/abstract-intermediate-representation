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
    'sscanf':   {'buf': 1, 'size': None},
    'fscanf':   {'buf': 2, 'size': None},

    # ===== Wide-char variants =====
    'wcscpy':   {'buf': 0, 'size': None},
    'wcsncpy':  {'buf': 0, 'size': 2},
    'swprintf': {'buf': 0, 'size': None},
}

USE_FUNCS = {
    # string sinks
    'puts':  {'buf': 0},
    'printf': {'buf': 1},     # printf('%s', buff)
    'fprintf': {'buf': 2},
    'strlen': {'buf': 0},
    'strcmp': {'buf': 0},
    'strchr': {'buf': 0},
    'strstr': {'buf': 0},
}

class AbstractBuilder:
    def __init__(self, code: bytes):
        self.code = code
        self.events = []
        self.struct_fields = {}
        self.pointer_vars = set()
        self.variable_data_type = {}

    def parse(self, root):
        self._visit(root)
        return self.events
    
    def _visit(self, node):
        handler = getattr(self, f'_handle_{node.type}', None)
        # print(self.struct_fields.keys(), self.struct_fields)
        if handler:
            handler(node)

        for child in node.children:
            self._visit(child)

    # ===== HANDLERS =====

    # def _handle_declaration(self, node):
    #     for child in node.named_children:
    #         if child.type == 'array_declarator':
    #             declarator = child
    #         elif child.type == 'init_declarator':
    #             declarator = child.child_by_field_name('declarator')
    #             value_node = child.child_by_field_name('value')

    #             if not declarator or declarator.type != 'array_declarator':
    #                 return
                

    #             name_node = declarator.child_by_field_name('declarator')

    #             if not name_node:
    #                 continue

    #             buf = utils.node_text(name_node, self.code)

    #             if value_node and value_node.type == 'string_literal':
    #                 literal = utils.node_text(value_node, self.code)

    #                 content = literal[1:-1]
    #                 size = SizeExpr("CONST", len(content) + 1)

    #                 self.events.append(
    #                     AbstractEvent(
    #                         kind="ALLOC",
    #                         buffer=buf,
    #                         size=size,
    #                         location=node.start_byte
    #                     )
    #                 )

    #             if not declarator or declarator.type != 'array_declarator':
    #                 var_node = child.child_by_field_name('declarator')
    #                 val_node = child.child_by_field_name('value')
    #                 if not var_node or not val_node:
    #                     continue

    #                 if val_node.type == 'call_expression':
    #                     fn = val_node.child_by_field_name('function')
    #                     args = val_node.child_by_field_name('arguments')

    #                     if fn and utils.node_text(fn, self.code) == 'strlen':
    #                         arg_nodes = list(args.named_children)
    #                         if len(arg_nodes) == 1:
    #                             dst = utils.node_text(var_node, self.code)
    #                             src = utils.node_text(arg_nodes[0], self.code)

    #                             self.events.append(
    #                                 AbstractEvent(
    #                                     kind='SIZE',
    #                                     buffer=dst,
    #                                     size=SizeExpr('EXPR', (f'strlen({src})', None, None)),
    #                                     location=node.start_byte
    #                                 )
    #                             )
    #                 continue
    #         else:
    #             continue

    #         name_node = declarator.child_by_field_name('declarator')
    #         size_node = declarator.child_by_field_name('size')

    #         if not name_node or not size_node:
    #             continue

    #         buf = utils.node_text(name_node, self.code)
    #         size_text = utils.node_text(size_node, self.code)

    #         try:
    #             size = utils.make_const(size_text)
    #         except ValueError:
    #             size = utils.make_var(size_text)

    #         self.events.append(
    #             AbstractEvent(
    #                 kind='ALLOC',
    #                 buffer=buf,
    #                 size=size,
    #                 location=node.start_byte
    #             )
    #         )

    # def _handle_declaration(self, node):
    #     for child in node.named_children:
    #         if child.type == 'struct_specifier':
    #             self._handle_struct_specifier_helper(child)
    #             continue

    #         if child.type == 'init_declarator':
    #             self._handle_init_declarator_helper(child, node.start_byte)
    #             continue

    #         if child.type == 'array_declarator':
    #             self._handle_array_declarator_helper(child, node.start_byte)

    def _handle_declaration(self, node):
        key = None
        var_name = None
        data_type = None
        name = None

        # for i, child in enumerate(node.named_children):
        #     fn = child.field_name_for_child(i)
        #     txt = utils.node_text(child, self.code)
        #     print(f'==={i}===')
        #     print(f'Fn: {fn}', f'Type: {child.type}')
        #     print('=======')
        #     print(txt)

        for child in node.named_children:
            if child.type == 'type_identifier':
                data_type = utils.node_text(child, self.code)

            if child.type == 'pointer_declarator':
                name = utils.node_text(child, self.code)

            if child.type == 'struct_specifier':
                key = id(child)
                self._handle_struct_specifier(child)

            if child.type == 'type_identifier':
                key = utils.node_text(child, self.code)

            if child.type == 'identifier':
                var_name = utils.node_text(child, self.code)
            
            if child.type == 'init_declarator':
                self._handle_init_declarator_helper(child, node.start_byte)

            if child.type == 'array_declarator':
                self._handle_array_declarator_helper(child, node.start_byte)

        self.variable_data_type[name] = data_type
        if key and var_name:
            fields = self.struct_fields.get(key, [])

            for field_name, size in fields:
                if size is None:
                    continue

                self.events.append(
                    AbstractEvent(
                        kind='ALLOC',
                        buffer=f'{var_name}.{field_name}',
                        size=SizeExpr('CONST', size),
                        location=node.start_byte
                    )
                )

    def _handle_array_declarator_helper(self, declarator, location):
        name_node = declarator.child_by_field_name('declarator')
        size_node = declarator.child_by_field_name('size')

        if not name_node or not size_node:
            return

        buf = utils.node_text(name_node, self.code)
        size_text = utils.node_text(size_node, self.code)

        try:
            size = utils.make_const(size_text)
        except ValueError:
            size = utils.make_var(size_text)

        self.events.append(
            AbstractEvent('ALLOC', buf, size, location)
        )

    def _handle_init_declarator_helper(self, node, location):
        declarator = node.child_by_field_name('declarator')
        value_node = node.child_by_field_name('value')

        if not declarator:
            return
        
        name_node = declarator
        if declarator.type == 'pointer_declarator':
            name_node = declarator.child_by_field_name('declarator')

        if declarator.type == 'array_declarator':
            name_node = declarator.child_by_field_name('declarator')
            size_node = declarator.child_by_field_name('size')

            buf = utils.node_text(name_node, self.code)

            if value_node and value_node.type == 'string_literal':
                literal = utils.node_text(value_node, self.code)
                size = SizeExpr('CONST', len(literal[1:-1]) + 1)

                self.events.append(
                    AbstractEvent('ALLOC', buf, size, location)
                )
                return

            if size_node:
                self._handle_array_declarator_helper(declarator, location)
                return
            
        if value_node and value_node.type == 'call_expression':
            fn = value_node.child_by_field_name('function')
            args = value_node.child_by_field_name('arguments')

            if fn and utils.node_text(fn, self.code) == 'strlen':
                arg = args.named_children[0]
                dst = utils.node_text(declarator, self.code)
                src = utils.node_text(arg, self.code)

                self.events.append(
                    AbstractEvent(
                        'SIZE',
                        dst,
                        SizeExpr('EXPR', (f'strlen({src})', None, None)),
                        location
                    )
                )

        if value_node.type == 'call_expression':
            fn = value_node.child_by_field_name('function')
            args = value_node.child_by_field_name('arguments')

            if not fn:
                return

            fn_name = utils.node_text(fn, self.code)
            if fn_name in ('malloc', 'calloc', 'realloc'):
                lhs_txt = utils.node_text(name_node, self.code)
                size_expr = self._extract_alloc_size(fn_name, args)
    
                self._update_region_source(
                    lhs_txt, size=size_expr, source='HEAP', location=location
                )

                key = self.variable_data_type.get(lhs_txt)
                if not key:
                    key = self.variable_data_type.get(f'*{lhs_txt}')

                fields = self.struct_fields.get(key, [])
                for field_name, size in fields:
                    if size is None:
                        continue
                    self.events.append(
                        AbstractEvent(
                            kind='ALLOC',
                            buffer=f'{lhs_txt}.{field_name}',
                            size=SizeExpr('CONST', size),
                            location=location
                        )
                    )

        var_name = utils.node_text(declarator, self.code)
        if hasattr(self, "pending_struct_fields") and self.pending_struct_fields:
            for field, size in self.pending_struct_fields:
                if size is None:
                    continue

                self.events.append(
                    AbstractEvent(
                        kind='ALLOC',
                        buffer=f'{var_name}.{field}',
                        size=SizeExpr('CONST', size),
                        location=location
                    )
                )

            self.pending_struct_fields = []

    def _handle_struct_specifier(self, node):
        fields = []
        key = id(node)
        # print('======================================================')
        # for i, child in enumerate(node.named_children):
        #     fn = node.field_name_for_child(i)
        #     txt = utils.node_text(child, self.code)
        #     print(f'==={i}===')
        #     print(f'Fn: {fn}', f'Type: {child.type}')
        #     print('=======')
        #     print(txt)
        for field in node.named_children:
            # print(utils.node_text(field, self.code), field.type)
            if field.type == 'type_identifier':
                key = utils.node_text(field, self.code)
            
            # if field.type == 'field_declaration_list':
            #     key = id(node)

            for decl in field.named_children:
                if decl.type != 'field_declaration':
                    continue

                declarator = decl.child_by_field_name('declarator')
                if declarator and declarator.type == 'array_declarator':
                    name_node = declarator.child_by_field_name('declarator')
                    size_node = declarator.child_by_field_name('size')

                    if not name_node or not size_node:
                        continue

                    field_name = utils.node_text(name_node, self.code)
                    size_text = utils.node_text(size_node, self.code)

                    try:
                        size = int(size_text)
                    except ValueError:
                        size = None

                    fields.append((field_name, size))
        # print(key)
        self.struct_fields[key] = fields

    # def _handle_field_declaration_list(self, node):
    #     fields = []
    #     # print(node.type)
    #     # print(utils.node_text(node, self.code))
    #     for field in node.named_children:
    #         for declarator in field.named_children:
    #             if declarator and declarator.type == 'array_declarator':
    #                 name_node = declarator.child_by_field_name('declarator')
    #                 size_node = declarator.child_by_field_name('size')

    #                 if not name_node or not size_node:
    #                     continue

    #                 field_name = utils.node_text(name_node, self.code)
    #                 size_text = utils.node_text(size_node, self.code)
    #                 try:
    #                     size = int(size_text)
    #                 except ValueError:
    #                     size = None

    #                 fields.append((field_name, size))

    #     self.struct_fields[id(node)] = fields

    def _handle_call_expression(self, node):
        func = node.child_by_field_name('function')
        args = node.child_by_field_name('arguments')

        if not func or not args:
            return
        
        func_name = utils.node_text(func, self.code)

        if func_name in WRITE_FUNCS:
            spec = WRITE_FUNCS[func_name]
            arg_nodes = list(args.named_children)

            buff_node = arg_nodes[spec['buf']]
            if spec['buf'] >= len(arg_nodes):
                return

            buff = utils.node_text(buff_node, self.code)

            size = None
            if spec['size'] is not None and spec['size'] < len(arg_nodes):
                size_node = arg_nodes[spec['size']]
                size_text = utils.node_text(size_node, self.code)
                try:
                    size = utils.make_const(size_text)
                except ValueError:
                    size = utils.make_var(size_text)

            self.events.append(
                AbstractEvent(kind='WRITE', buffer=buff, size=size, location=node.start_byte)
            )
        elif func_name in USE_FUNCS:
            spec = USE_FUNCS[func_name]
            arg_nodes = list(args.named_children)

            if spec['buf'] >= len(arg_nodes):
                return
            
            buff = utils.node_text(arg_nodes[spec['buf']], self.code)
            buff = buff.split('[', 1)[0]
            
            self.events.append(
                AbstractEvent(
                    kind='USE',
                    buffer=buff,
                    location=node.start_byte
                )
            )
    
    def _handle_if_statement(self, node):
        cond = node.child_by_field_name('condition')
        if not cond:
            return
        
        text = utils.node_text(cond, self.code)
        text = self._strip_parens(text)
        
        sub_conds = self._split_logical_conditions(text)

        for sub in sub_conds:
            sub = sub.strip()

            for op in ['<=', '<', '>=', '>', '==', '!=']:
                if op in sub:
                    left, right = self._split_condition(sub)

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
                    break
    
    def _handle_assignment_expression(self, node):
        lhs = node.child_by_field_name('left')
        rhs = node.child_by_field_name('right')

        if not lhs or not rhs:
            return
        
        if lhs.type == 'subscript_expression':
            arr = lhs.child_by_field_name('argument')
            idx = lhs.child_by_field_name('index')

            if not arr:
                return

            buf = utils.node_text(arr, self.code)
            size = None
            if idx:
                idx_text = utils.node_text(idx, self.code)
                try:
                    size = utils.make_const(idx_text)
                except ValueError:
                    size = utils.make_var(idx_text)

            self.events.append(
                AbstractEvent(
                    kind='WRITE',
                    buffer=buf,
                    size=size,
                    location=node.start_byte
                )
            )

        if lhs.type == 'pointer_expression':
            arg = lhs.child_by_field_name('argument')
            if arg:
                buf = utils.node_text(arg, self.code)
                buf = self._alphanum(buf)
                self.events.append(
                    AbstractEvent('PTR_WRITE', buf, location=node.start_byte)
                )

        if rhs.type == 'cast_expression':
            rhs = rhs.child_by_field_name('value')

        if rhs.type == 'call_expression':
            fn = rhs.child_by_field_name('function')
            args = rhs.child_by_field_name('arguments')

            if fn:
                fn_name = utils.node_text(fn, self.code)
                if fn_name in ('malloc', 'calloc', 'realloc'):
                    lhs_txt = utils.node_text(lhs, self.code)
                    size_expr = self._extract_alloc_size(fn_name, args)

                    self._update_region_source(
                        lhs_txt, size=size_expr, source='HEAP', location=node.start_byte
                    )

                    # print(self.variable_data_type)
                    key = self.variable_data_type.get(lhs_txt)
                    if not key:
                        key = self.variable_data_type.get(f'*{lhs_txt}')
                    # print(key)

                    fields = self.struct_fields.get(key, [])
                    for field_name, size in fields:
                        if size is None:
                            continue

                        self.events.append(
                            AbstractEvent(
                                kind='ALLOC',
                                buffer=f'{lhs_txt}.{field_name}',
                                size=SizeExpr('CONST', size),
                                location=node.start_byte
                            )
                        )


                    return


    def _handle_pointer_declarator(self, node):
        name_node = node.child_by_field_name('declarator')
        if not name_node:
            return

        buf = utils.node_text(name_node, self.code)
        self.pointer_vars.add(buf)

        self.events.append(
            AbstractEvent(
                kind='REGION',
                buffer=buf,
                size=SizeExpr('UNKNOWN', None),
                source='UNKNOWN',
                location=node.start_byte
            )
        )

    def _handle_parameter_declaration(self, node):
        decl = node.child_by_field_name('declarator')
        if not decl or decl.type != 'pointer_declarator':
            return

        name = utils.node_text(
            decl.child_by_field_name('declarator'),
            self.code
        )

        self.pointer_vars.add(name)
        self.events.append(
            AbstractEvent(
                kind='REGION',
                buffer=name,
                size=SizeExpr('UNKNOWN', None),
                source='EXTERNAL',
                location=node.start_byte
            )
        )

    def _handle_update_expression(self, node):
        arg = node.child_by_field_name('argument')
        if not arg:
            return
        
        buf = utils.node_text(arg, self.code)
        if buf in self.pointer_vars:
            self.events.append(
                AbstractEvent('PTR_ADVANCE', buf, location=node.start_byte)
            )
    
    def _handle_while_statement(self, node):
        cond = node.child_by_field_name('condition')
        body = node.child_by_field_name('body')

        if not cond or not body:
            return

        text = utils.node_text(cond, self.code)
        # if '--' in text or '<' in text or '<=' in text or '++' in text:
        #     var = self._strip_parens(text)

        #     self.events.append(
        #         AbstractEvent('LOOP_BEGIN', var, location=node.start_byte)
        #     )

        #     self._visit(body)

        #     self.events.append(
        #         AbstractEvent('LOOP_END', location=node.end_byte)
        #     )

        #     return

        rand_id = shortuuid.random(length=3)
        var = self._strip_parens(text)
        self.events.append(
            AbstractEvent(f'LOOP_BEGIN', var, unique_id=rand_id, location=node.start_byte)
        )

        self._visit(body)

        self.events.append(
            AbstractEvent(f'LOOP_END', unique_id=rand_id, location=node.end_byte)
        )

        return
    
    def _handle_for_statement(self, node):
        cond = node.child_by_field_name('condition')
        body = node.child_by_field_name('body')

        if not cond or not body:
            return

        text = utils.node_text(cond, self.code)
        
        rand_id = shortuuid.random(length=3)
        var = self._strip_parens(text)
        self.events.append(
            AbstractEvent(f'LOOP_BEGIN', var, unique_id=rand_id, location=node.start_byte)
        )

        self._visit(body)

        self.events.append(
            AbstractEvent(f'LOOP_END', unique_id=rand_id, location=node.end_byte)
        )


    # ===== END OF HANDLERS =====

    def _split_condition(self, cond):
        parts = re.split(r'(<=|>=|==|!=|<|>)', cond)
        if len(parts) != 3:
            return None, None
        left, _, right = parts
        return left.strip(), right.strip()

    def _split_logical_conditions(self, text):
        return re.split(r'\s*&&\s*|\s*\|\|\s*', text)
    
    def _strip_parens(self, text: str) -> str:
        text = text.strip()
        if text.startswith('(') and text.endswith(')'):
            return text[1:-1].strip()
        return text
    
    def _is_pointer(self, node):
        name = utils.node_text(node, self.code)
        return name in self.pointer_vars
    
    def _update_region_source(self, buf, size, source, location):
        for e in reversed(self.events):
            if e.kind == 'REGION' and e.buffer == buf:
                e.source = source
                e.size = size
                return

        # fallback (should rarely happen)
        self.events.append(
            AbstractEvent(
                kind='REGION',
                buffer=buf,
                size=size or SizeExpr('UNKNOWN', None),
                source=source,
                location=location
            )
        )

    def _extract_alloc_size(self, fn_name, args):
        arg_nodes = list(args.named_children)

        if fn_name == 'malloc':
            # malloc(size)
            if len(arg_nodes) >= 1:
                return self._size_from_node(arg_nodes[0])

        elif fn_name == 'calloc':
            # calloc(nmemb, size)
            if len(arg_nodes) >= 2:
                return SizeExpr(
                    'EXPR',
                    (utils.node_text(arg_nodes[0], self.code),
                    '*',
                    utils.node_text(arg_nodes[1], self.code))
                )

        elif fn_name == 'realloc':
            # realloc(ptr, size)
            if len(arg_nodes) >= 2:
                return self._size_from_node(arg_nodes[1])

        return SizeExpr('UNKNOWN', None)

    def _size_from_node(self, node):
        txt = utils.node_text(node, self.code)
        try:
            return SizeExpr('CONST', int(txt))
        except ValueError:
            return SizeExpr('VAR', txt)



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

        self.events = unique

    def _alphanum(self, str):
        return re.sub(r'[^a-zA-Z0-9]', '', str)

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

            elif ev.kind == 'ALLOC':
                base = ev.buffer.replace('->', ' -> ').replace('.', ' ').split()[0]
                if ev.buffer in last_size:
                    dfg_event[idx].add(last_size[ev.buffer])
                last_region[base] = idx

            elif ev.kind == 'SIZE':
                if ev.buffer in last_region:
                    dfg_event[idx].add(last_region[ev.buffer])
                last_size[ev.buffer] = idx

            elif ev.kind == 'WRITE':
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

                last_ptr[ev.buffer] = idx

            elif ev.kind == 'PTR_ADVANCE':
                if ev.buffer in last_ptr:
                    dfg_event[idx].add(last_ptr[ev.buffer])

                if loop_stack:
                    for i, _ in reversed(loop_stack):
                        dfg_event[idx].add(i)

                last_ptr[ev.buffer] = idx

            elif ev.kind == 'CONSTRAINT':
                last_constraint[ev.size.value[0]] = idx

            elif ev.kind == 'LOOP_BEGIN':
                val = self._alphanum(ev.buffer)[0]

                if val in last_constraint:
                    dfg_event[idx].add(last_constraint[val])
                    
                # loop_stack.append(idx)
                loop_stack.append((idx, val))

            elif ev.kind == 'LOOP_END':
                loop_stack.pop()

        # print(last_constraint)

        # ---- Phase 3: convert to GraphCodeBERT DFG ----
        dfg = []

        for dst_event, src_events in dfg_event.items():
            dst_start, dst_end = event_spans[dst_event]
            ev = self.events[dst_event]

            # if ev.buffer:
            #     base = ev.buffer.split('->')[0]
            #     try:
            #         dst_token = tokens.index(base, dst_start, dst_end)
            #     except ValueError:
            #         dst_token = dst_start
            # else:
            #     dst_token = dst_start
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