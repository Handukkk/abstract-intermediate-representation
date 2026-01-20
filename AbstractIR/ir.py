from dataclasses import dataclass
from typing import Optional, Union

@dataclass
class SizeExpr:
    kind: str       # CONST | STR | EXPR
    value: any

    def __str__(self):
        if self.kind == 'CONST':
            return f'SIZE_{str(self.value)}'
        if self.kind == 'IDX':
            return f'INDEX_{self.value}'
        if self.kind == 'EXPR':
            left, op, right = self.value
            return f"{left}{' ' if op else ''}{op if op else ''}{' ' if right else ''}{right if right else ''}"
        return 'SIZE_UNKNOWN'

@dataclass
class AbstractEvent:
    kind: str                       # ALLOC | WRITE | CONSTRAINT | USE | SIZE | REGION | PTR_WRITE | PTR_ADVANCE | LOOP_BEGIN | LOOP_END
    buffer: Optional[str] = None
    size: Optional[str] = None
    location: Optional[int] = None  # AST node id
    source: Optional[str] = None
    unique_id: Optional[str] = None

    def __str__(self):
        if self.kind == 'ALLOC':
            size = str(self.size) if self.size else 'UNKNOWN'
            return f'{self.kind}({self.buffer}, {size})'
        if self.kind.startswith('WRITE_'):
            size = str(self.size) if self.size else 'UNKNOWN'
            return f'{self.kind}({self.buffer}, {size})'
        if self.kind == 'CONSTRAINT':
            return f'CONSTRAINT({self.size})'
        if self.kind == 'SIZE':
            return f'SIZE({self.buffer} = {self.size})'
        if self.kind == 'USE':
            return f'USE({self.buffer})'
        if self.kind == 'REGION':
            return f'REGION({self.buffer}, {self.size}, {self.source})'
        if self.kind == 'PTR_WRITE':
            size = str(self.size) if self.size else 'UNKNOWN'
            return f'PTR_WRITE({self.buffer})'
        if self.kind == 'PTR_ADVANCE':
            return f'PTR_ADVANCE({self.buffer})'
        if self.kind == 'LOOP_BEGIN':
            return f'LOOP_BEGIN({self.buffer})'
        
        return f'{self.kind}'