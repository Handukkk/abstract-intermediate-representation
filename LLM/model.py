import os
from openai import OpenAI

class ValidatorLLM:
    def __init__(self, model=None, api_key=None):
        self.model = model
        self.client = OpenAI(
            base_url="https://router.huggingface.co/v1",
            api_key=api_key,
        )

        base_dir = os.path.dirname(os.path.abspath(__file__))
        system_prompt_path = os.path.join(base_dir, 'system_prompt')

        with open(os.path.join(system_prompt_path, 'buffer_overflow.md'), 'r') as f:
            self.system_prompt = f.read()

    def predict(self, code, document=None):
        code_content = ""
        code_content += f"Funcs: \n{code.get('func')}\n"
        code_content += "Abstract-IR: \n"
        code_content += "\n".join(code.get('abstract-ir', []))

        prompt = None
        if document:
            helper_content = ""
            for r in document:
                helper_content += f"Similarity Score: {r.get('score')}\n"
                helper_content += f"Funcs: \n{r.get('func')}\n\n"
                helper_content += "Abstract-IR: \n"
                helper_content += "\n".join(r.get('abstract-ir', []))
                helper_content += "\n\n---\n\n"

            prompt = f'''
Here is some helper document that you can use to help analyzing the code. 
The document is some example of vulnerable code, please use this document as a reference.
Analyze the given function, analyze the behaviour, compare it with the reference code's behaviour, if it have a similarity, it's likely to be vulnerable.
Don't conclude the function is safe just because it wasn't similar to the reference syntactically, remember, vulnerability is in the flow, not in the syntax.

{helper_content}

Check this code
{code_content}
'''
        else:
            prompt = f'''
Check this code

{code_content}
'''
        completion = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": self.system_prompt
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
        )

        return int(completion.choices[0].message.content.strip())
    