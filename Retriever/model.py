import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
import torch
import numpy as np
from collections import defaultdict
from transformers import RobertaTokenizer, RobertaModel


class GraphCodeBERTEmbedder:
    def __init__(self, device=None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(base_dir, 'model')

        self.tokenizer = RobertaTokenizer.from_pretrained(model_path)
        self.model = RobertaModel.from_pretrained(model_path, add_pooling_layer=False)

        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.model.eval()

    def build_inputs(self, ir_tokens, dfg):
        ir_len = len(ir_tokens)

        dfg_nodes = list({name for name, _, _ in dfg})

        dfg_to_code = defaultdict(set)
        for name, dst_idx, src_idxs in dfg:
            dfg_idx = dfg_nodes.index(name)
            dfg_to_code[dfg_idx].add(dst_idx)
            for s in src_idxs:
                dfg_to_code[dfg_idx].add(s)

        final_tokens = ir_tokens + dfg_nodes

        encoding = self.tokenizer(
            final_tokens,
            is_split_into_words=True,
            return_tensors='pt',
            add_special_tokens=True
        )

        input_ids = encoding['input_ids'].to(self.device)
        seq_len = input_ids.size(1)

        position_ids = torch.arange(seq_len).tolist()
        for dfg_idx, code_idxs in dfg_to_code.items():
            pos = int(sum(code_idxs) / len(code_idxs))
            position_ids[ir_len + dfg_idx] = pos

        position_ids = torch.tensor([position_ids], device=self.device)

        attn = torch.zeros(seq_len, seq_len, device=self.device)
        attn[:ir_len, :ir_len] = 1

        for dfg_idx, code_idxs in dfg_to_code.items():
            for c in code_idxs:
                attn[ir_len + dfg_idx, c] = 1
                attn[c, ir_len + dfg_idx] = 1

        return {
            'input_ids': input_ids,
            'attention_mask': attn.unsqueeze(0),
            'position_ids': position_ids,
        }


    @torch.no_grad()
    def embed(self, ir_tokens, dfg):
        inputs = self.build_inputs(ir_tokens, dfg)
        outputs = self.model(**inputs)

        cls_embedding = outputs.last_hidden_state[:, 0, :]
        return cls_embedding.squeeze(0).cpu().numpy()
