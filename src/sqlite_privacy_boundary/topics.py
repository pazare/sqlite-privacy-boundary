"""Deterministic topic grouping for short free-text records."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field

Vector = list[float]

EMBED_DIM = 256
CLUSTER_THRESHOLD = 0.10

_STOPWORDS = frozenset(
    """a an and are as at be but by for from has have i if in is it its of on or
    that the their them they this to was we were will with you your our us my me
    not no do does did so just really very can could would should about more most
    need needs want wants get got like than then there here what when who how
    feel feels felt been being keep keeps people group record records data item
    items text texts issue issues thing things going actually getting lot something
    someone able years year months month time way ways better best help right now
    days every around use using see seen tell told know out much sure maybe also
    even still put dont don im ive cant wont isnt ill youre theyre thats gonna""".split()
)
_WORD = re.compile(r"[a-z0-9]+")
_POS = frozenset(
    "good great support useful excellent safe better improve improved fair clean strong".split()
)
_NEG = frozenset(
    "bad worse worst unsafe unfair broken fail failing failed expensive dangerous worried crisis".split()
)
_NEGATORS = frozenset("not no never nor cannot without dont cant wont isnt doesnt didnt".split())


@dataclass
class Topic:
    members: list[int] = field(default_factory=list)
    texts: list[str] = field(default_factory=list)
    centroid: Vector = field(default_factory=list)
    label: str = ""
    sentiment: float = 0.0

    @property
    def size(self) -> int:
        return len(self.members)


def _tokens(text: str) -> list[str]:
    return [w for w in _WORD.findall(text.lower()) if len(w) >= 2 and w not in _STOPWORDS]


def _hash_term(term: str) -> tuple[int, int]:
    digest = hashlib.blake2b(term.encode("utf-8"), digest_size=8).digest()
    value = int.from_bytes(digest, "big")
    return value, (1 if (value >> 32) & 1 else -1)


def embed(text: str, dim: int = EMBED_DIM) -> Vector:
    vec = [0.0] * dim
    for term in _tokens(text):
        value, sign = _hash_term(term)
        vec[value % dim] += sign
    return _normalize(vec)


def cosine(a: Vector, b: Vector) -> float:
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return sum(x * y for x, y in zip(a, b)) / (na * nb)


def sentiment_score(text: str) -> float:
    words = _WORD.findall(text.lower())
    pos = neg = 0
    for i, word in enumerate(words):
        negated = any(x in _NEGATORS for x in words[max(0, i - 3):i])
        if word in _POS:
            neg, pos = (neg + 1, pos) if negated else (neg, pos + 1)
        elif word in _NEG:
            pos, neg = (pos + 1, neg) if negated else (pos, neg + 1)
    if pos == 0 and neg == 0:
        return 0.0
    return (pos - neg) / (pos + neg)


def cluster(documents: list[tuple[int, str]], threshold: float = CLUSTER_THRESHOLD) -> list[Topic]:
    topics: list[Topic] = []
    for row_id, text in documents:
        vec = embed(text)
        best_index: int | None = None
        best_sim = threshold
        for i, topic in enumerate(topics):
            sim = cosine(vec, topic.centroid)
            if sim > best_sim:
                best_sim, best_index = sim, i
        if best_index is None:
            topics.append(Topic(members=[row_id], texts=[text], centroid=vec))
        else:
            topic = topics[best_index]
            topic.centroid = _update_mean(topic.centroid, topic.size, vec)
            topic.members.append(row_id)
            topic.texts.append(text)
    _label_all(topics, documents)
    return topics


def _normalize(vec: Vector) -> Vector:
    norm = math.sqrt(sum(x * x for x in vec))
    return [x / norm for x in vec] if norm else vec


def _update_mean(mean: Vector, size: int, vec: Vector) -> Vector:
    return [(m * size + v) / (size + 1) for m, v in zip(mean, vec)]


def _content_words(text: str) -> set[str]:
    return {w for w in _WORD.findall(text.lower()) if len(w) >= 3 and w not in _STOPWORDS}


def _label_all(topics: list[Topic], documents: list[tuple[int, str]]) -> None:
    df: Counter[str] = Counter()
    for _, text in documents:
        df.update(_content_words(text))
    n_docs = len(documents)
    for topic in topics:
        topic.label = ", ".join(_top_terms(topic.texts, df, n_docs)) or "(unlabelled)"
        topic.sentiment = sum(sentiment_score(text) for text in topic.texts) / max(1, topic.size)


def _top_terms(texts: list[str], df_corpus: Counter[str], n_docs: int, k: int = 4) -> list[str]:
    df_topic: Counter[str] = Counter()
    for text in texts:
        df_topic.update(_content_words(text))

    def score(word: str) -> float:
        return df_topic[word] * math.log(1.0 + n_docs / (1.0 + df_corpus.get(word, 0)))

    return sorted(df_topic, key=lambda word: (-score(word), word))[:k]
