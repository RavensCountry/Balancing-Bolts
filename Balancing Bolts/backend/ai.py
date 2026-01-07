import os
import json
from typing import List
import openai
import numpy as np
from .database import get_session
from .models import Embedding

openai.api_key = os.getenv("OPENAI_API_KEY")

def embed_text(text: str) -> List[float]:
    if not openai.api_key:
        raise RuntimeError("OPENAI_API_KEY not set")
    res = openai.Embedding.create(model="text-embedding-3-small", input=text)
    return res["data"][0]["embedding"]


def store_embedding(source_type: str, source_id: int, text: str):
    vec = embed_text(text)
    with get_session() as s:
        e = Embedding(source_type=source_type, source_id=source_id, vector=json.dumps(vec), text=text)
        s.add(e)
        s.commit()
        s.refresh(e)
        return e


def query_embeddings(query: str, top_k: int = 5):
    qvec = np.array(embed_text(query))
    with get_session() as s:
        from sqlmodel import select
        rows = s.exec(select(Embedding)).all()
        scored = []
        for r in rows:
            try:
                vec = np.array(json.loads(r.vector))
            except Exception:
                continue
            denom = (np.linalg.norm(qvec) * np.linalg.norm(vec) + 1e-10)
            sim = float(np.dot(qvec, vec) / denom)
            scored.append((sim, r))
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[:top_k]


def answer_query(query: str) -> str:
    # retrieve top docs and ask OpenAI to answer using them
    try:
        docs = query_embeddings(query, top_k=5)
    except Exception as e:
        return f"Error retrieving docs: {e}"
    context_parts = []
    for score, doc in docs:
        context_parts.append(f"SOURCE: {doc.source_type} (id={doc.source_id})\n{doc.text}")
    context = "\n\n".join(context_parts)
    prompt = f"You are an assistant that answers questions about apartment inventory and invoices. Use only the provided sources.\n\nSOURCES:\n{context}\n\nQUESTION: {query}\n\nAnswer concisely with numbers and units where appropriate."
    if not openai.api_key:
        return "OpenAI API key not configured. Set OPENAI_API_KEY."
    resp = openai.ChatCompletion.create(model="gpt-4o-mini", messages=[{"role":"user","content":prompt}], max_tokens=500)
    return resp["choices"][0]["message"]["content"]
