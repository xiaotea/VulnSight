from __future__ import annotations
import os
import json
import hashlib
from typing import Callable, List, Dict, Tuple

from .types import VulnKnowledge, PredictionResult, CodeBlock
from .semantic_reconstruction import (
    reconstruct_semantic_structures,
    SemanticReconstructionConfig,
    SemanticReconstructionOutput,
)
from .preprocess_target import build_candidate_space, LSHConfig, compute_global_symbols
from .prompt_decision import match_with_patterns

LLMFunc = Callable[[str], str]


# =========================
#  持久化缓存：辅助类 & 函数
# =========================

class _CachedPattern:
    """
    轻量级模式对象，只实现 to_prompt_dict()，
    供决策阶段使用（match_with_patterns 只用到这一点）。
    """
    def __init__(self, data: dict):
        self._data = data

    @property
    def key_blocks(self):
        return self._data.get("key_blocks", [])

    def to_prompt_dict(self) -> dict:
        return self._data


class _CachedSemOut:
    """
    用于从 JSON 还原的语义重建结果。
    只保留当前 pipeline 实际用到的三个字段：
      - patterns.vuln_pattern / safe_pattern（仅用于 to_prompt_dict）
      - vuln_blocks
      - fix_blocks
    """
    def __init__(
        self,
        vuln_pattern_dict: dict,
        safe_pattern_dict: dict,
        vuln_blocks: List[CodeBlock],
        fix_blocks: List[CodeBlock],
    ):
        # patterns 模拟原来的 PatternPair 结构
        class _Patterns:
            def __init__(self, vp: dict, sp: dict):
                self.vuln_pattern = _CachedPattern(vp)
                self.safe_pattern = _CachedPattern(sp)

        self.patterns = _Patterns(vuln_pattern_dict, safe_pattern_dict)
        self.vuln_blocks = vuln_blocks
        self.fix_blocks = fix_blocks


def _cache_dir() -> str:
    """
    返回 ./cache 目录路径，并确保存在。
    相对当前进程运行目录。
    """
    d = os.path.join(os.getcwd(), "cache")
    os.makedirs(d, exist_ok=True)
    return d


def _cache_path_for_key(cache_key: str) -> str:
    """
    根据 cache_key 生成 JSON 文件名。
    例如:
      cve:CVE-2023-12345 -> ./cache/cve_CVE-2023-12345.json
    """
    safe_key = cache_key.replace(":", "_")
    return os.path.join(_cache_dir(), safe_key + ".json")


def _codeblock_to_dict(b: CodeBlock) -> dict:
    return {
        "id": b.id,
        "file_path": b.file_path,
        "start_line": b.start_line,
        "end_line": b.end_line,
        "content": b.content,
        "language": b.language,
        "metadata": getattr(b, "metadata", {}) or {},
    }


def _codeblock_from_dict(d: dict) -> CodeBlock:
    return CodeBlock(
        id=d.get("id"),
        file_path=d.get("file_path"),
        start_line=d.get("start_line"),
        end_line=d.get("end_line"),
        content=d.get("content"),
        language=d.get("language"),
        metadata=d.get("metadata") or {},
    )


def _save_semantic_cache_to_json(
    cache_key: str,
    sem_out: SemanticReconstructionOutput,
) -> None:
    """
    将语义重建结果的关键信息序列化到 ./cache/*.json 中。
    只保存：
      - vuln_pattern.to_prompt_dict()
      - safe_pattern.to_prompt_dict()
      - vuln_blocks / fix_blocks（以 CodeBlock 的字段序列化）
    """
    try:
        vp_dict = sem_out.patterns.vuln_pattern.to_prompt_dict()
        sp_dict = sem_out.patterns.safe_pattern.to_prompt_dict()
    except Exception:
        # 如果 patterns 结构不符合预期，就不做持久化，避免影响主逻辑
        return

    data = {
        "vuln_pattern": vp_dict,
        "safe_pattern": sp_dict,
        "vuln_blocks": [_codeblock_to_dict(b) for b in sem_out.vuln_blocks],
        "fix_blocks": [_codeblock_to_dict(b) for b in sem_out.fix_blocks],
    }

    path = _cache_path_for_key(cache_key)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
    except OSError:
        # IO 失败不影响主流程
        return


def _load_semantic_cache_from_json(cache_key: str) -> _CachedSemOut | None:
    """
    尝试从 ./cache/cache_key.json 读取缓存。
    如果文件不存在或格式不对，返回 None。
    """
    path = _cache_path_for_key(cache_key)
    if not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None

    try:
        vp = data["vuln_pattern"]
        sp = data["safe_pattern"]
        vuln_blocks = [_codeblock_from_dict(d) for d in data.get("vuln_blocks", [])]
        fix_blocks = [_codeblock_from_dict(d) for d in data.get("fix_blocks", [])]
    except Exception:
        return None

    return _CachedSemOut(vp, sp, vuln_blocks, fix_blocks)


# =========================
#  VulnSight 主类
# =========================

class VulnSight:
    """VulnSight 顶层封装：FVulnSight(Ct, Iv)."""

    def __init__(
        self,
        llm: LLMFunc,
        language_hint: str = "",
        hits_top_k: int = 20,
        jaccard_threshold: float = 0.6,
        num_perm: int = 64,
        cache_enabled: bool = True,
    ):
        self.llm = llm
        self.language_hint = language_hint
        self.sem_cfg = SemanticReconstructionConfig(
            hits_top_k=hits_top_k,
            language_hint=language_hint,
        )
        self.lsh_cfg = LSHConfig(
            num_perm=num_perm,
            jaccard_threshold=jaccard_threshold,
        )
        self.cache_enabled = cache_enabled

        # 进程内缓存：key -> SemanticReconstructionOutput 或 _CachedSemOut
        self._sem_cache: Dict[str, SemanticReconstructionOutput | _CachedSemOut] = {}

    def _make_cache_key(self, vuln: VulnKnowledge) -> str:
        """
        统一生成缓存 key。
        优先使用 cve_id；否则用 desc+patch_diff 的 hash。
        """
        if getattr(vuln, "cve_id", None):
            return f"cve:{vuln.cve_id}"
        h = hashlib.sha256()
        h.update((vuln.desc or "").encode("utf-8", errors="ignore"))
        h.update((vuln.patch_diff or "").encode("utf-8", errors="ignore"))
        return f"anon:{h.hexdigest()[:16]}"

    def _semantic_phase(self, vuln: VulnKnowledge):
        """
        第 1 阶段：基于漏洞知识 Iv = (Dv, Pv, 脆弱/修复版本代码) 做语义重建。
        带缓存。
        """
        cache_key = self._make_cache_key(vuln)

        # 1) 内存缓存命中
        if self.cache_enabled and cache_key in self._sem_cache:
            return self._sem_cache[cache_key]

        # 2) JSON 文件缓存命中
        if self.cache_enabled:
            cached = _load_semantic_cache_from_json(cache_key)
            if cached is not None:
                self._sem_cache[cache_key] = cached
                return cached

        # 3) 正常调用语义重建
        sem_out = reconstruct_semantic_structures(
            vuln=vuln,
            llm=self.llm,
            cfg=self.sem_cfg,
        )

        # 4) 写入缓存
        if self.cache_enabled:
            self._sem_cache[cache_key] = sem_out
            _save_semantic_cache_to_json(cache_key, sem_out)

        return sem_out

    def _build_Bvref(self, sem_out) -> List[CodeBlock]:
        """
        sem_out 既可以是真正的 SemanticReconstructionOutput，
        也可以是 _CachedSemOut（duck typing）。
        """
        merged: Dict[str, CodeBlock] = {}
        for b in (sem_out.vuln_blocks + sem_out.fix_blocks):
            merged[b.id] = b
        return list(merged.values())

    def preprocess_target(
        self,
        target_root: str,
        Bvref: List[CodeBlock],
        vuln: VulnKnowledge,
    ):
        # 1) 候选空间 + 全局符号：build_candidate_space 已经返回三元组
        Bt, Scand, global_signals = build_candidate_space(
            target_root=target_root,
            Bvref=Bvref,
            llm=self.llm,
            lsh_cfg=self.lsh_cfg,
            vuln=vuln,
            language_hint=self.language_hint,
        )

        return Bt, Scand, global_signals

    def verify(self, target_root: str, vuln: VulnKnowledge) -> PredictionResult:
        # 1) 语义重建（可能走缓存）
        sem_out = self._semantic_phase(vuln)

        vuln_pattern = sem_out.patterns.vuln_pattern
        safe_pattern = sem_out.patterns.safe_pattern

        # 2) 参考漏洞/修复代码块
        Bvref = self._build_Bvref(sem_out)

        # 3) 目标项目预处理：全项目块 Bt、候选块 Scand、全局符号 global_signals
        Bt, Scand, global_signals = self.preprocess_target(target_root, Bvref, vuln)

        # 4) 最终 LLM 决策 —— 把 Bvref 和 global_signals 都传进去
        result = match_with_patterns(
            self.llm,
            vuln_info=vuln,
            vuln_pattern=vuln_pattern,
            safe_pattern=safe_pattern,
            Scand=Scand,
            Bvref=Bvref,
            global_signals=global_signals,
        )
        return result
