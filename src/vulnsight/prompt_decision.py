from __future__ import annotations
import json
from typing import List, Callable, Set, Tuple, Dict, Optional
import re
import os
from textwrap import shorten
from .types import CodeBlock, VulnPattern, SafePattern, PredictionResult, VulnKnowledge
from .types import CodeSpan

LLMFunc = Callable[[str], str]


def _extract_important_basenames(
    vuln_pattern: VulnPattern,
    safe_pattern: SafePattern,
    vuln_info: VulnKnowledge,
) -> Set[str]:
    names: Set[str] = set()

    def _from_key_blocks(pattern):
        blocks = getattr(pattern, "key_blocks", None)

        # 兼容缓存对象 / 轻量对象
        if blocks is None and hasattr(pattern, "to_prompt_dict"):
            blocks = (pattern.to_prompt_dict() or {}).get("key_blocks", [])

        for p in blocks or []:
            path = None

            if isinstance(p, CodeSpan):
                path = p.file_path
            elif isinstance(p, str):
                # 用 rsplit，避免路径中可能再出现冒号分隔问题
                path = p.rsplit(":", 1)[0]
            elif isinstance(p, dict):
                path = p.get("file_path")

            if path:
                names.add(os.path.basename(path))

    _from_key_blocks(vuln_pattern)
    _from_key_blocks(safe_pattern)

    # 再从 patch diff 里粗暴扫一下 *.java / *.py 文件名
    diff = vuln_info.patch_diff or ""
    for m in re.finditer(r"([A-Za-z0-9_]+\.java|[A-Za-z0-9_]+\.py)", diff):
        names.add(m.group(1))

    return names

def match_with_patterns(
    llm: LLMFunc,
    vuln_info: VulnKnowledge,
    vuln_pattern: VulnPattern,
    safe_pattern: SafePattern,
    Scand: List[CodeBlock],
    Bvref: Optional[List[CodeBlock]] = None,
    global_signals: Optional[Dict[str, bool]] = None,
) -> PredictionResult:
    from textwrap import shorten as _shorten

    if global_signals is None:
        global_signals = {}

    has_decoding_exception = bool(global_signals.get("has_DecodingException", False))
    has_is_payload_valid = bool(global_signals.get("has_isPayloadValid", False))

    important_basenames = _extract_important_basenames(
        vuln_pattern, safe_pattern, vuln_info
    )

    def _prioritize_blocks(blocks: List[CodeBlock]) -> List[CodeBlock]:
        def _score(b: CodeBlock) -> Tuple[int, str]:
            base = os.path.basename(b.file_path or "")
            # 重要文件优先，其次按文件名排序保证稳定性
            return (0 if base in important_basenames else 1, base)
        return sorted(blocks, key=_score)

    # 用于 Bvref 的简略展示（始终精简，避免把参考代码撑爆）
    def _blocks_to_brief(blocks: List[CodeBlock], limit: int = 20, width: int = 260) -> str:
        blocks = _prioritize_blocks(blocks)
        parts = []
        for b in blocks[:limit]:
            content = b.content or ""
            snippet = _shorten(
                content.replace("\n", " "),
                width=width,
                placeholder="...",
            )
            short_path = os.path.basename(b.file_path or "")
            parts.append(f"[{short_path}:{b.start_line}-{b.end_line}] {snippet}")
        return "\n".join(parts)

    # 第 1 轮：让 LLM 先选出「需要展开全文」的关键块
    def _make_stage1_listing(blocks: List[CodeBlock], limit: int = 80, width: int = 160) -> str:
        blocks = _prioritize_blocks(blocks)
        parts = []
        for b in blocks[:limit]:
            content = b.content or ""
            snippet = _shorten(
                content.replace("\n", " "),
                width=width,
                placeholder="...",
            )
            base = os.path.basename(b.file_path or "")
            name = (b.metadata or {}).get("name") or ""
            parts.append(
                f"ID={b.id} | [{base}:{b.start_line}-{b.end_line}] name={name} :: {snippet}"
            )
        return "\n".join(parts)

    # ① 参考漏洞/修复版本代码块（给模型看“原版”模式），始终用简略版
    Bvref = Bvref or []
    Bvref_brief = _blocks_to_brief(Bvref, limit=20, width=260)

    # ---------- Stage 1：选重要块 ----------
    Scand_stage1_str = _make_stage1_listing(Scand, limit=80, width=160)

    vp = vuln_pattern.to_prompt_dict()
    sp = safe_pattern.to_prompt_dict()
    pattern_json = json.dumps({"vuln_pattern": vp, "safe_pattern": sp}, indent=2)

    stage1_template = """
You are an expert in software vulnerabilities.

This is STEP 1 of a two-step analysis.

Goal of this step:
Given a list of candidate code blocks in the TARGET project, select the SMALL subset of blocks that are most important for deciding whether the vulnerability reappears.

Context:
1) Dv (official vulnerability description):
{desc}

2) Semantic patterns (reconstructed from vulnerable/fixed versions):
{pattern_json}

3) Brief reference code blocks (Bv_ref):
{Bvref_brief}

4) Candidate code blocks in the TARGET project (Scand), summarized:
Each line has a unique "ID=" followed by file, lines, optional name, and a short snippet.
You MUST use these IDs to refer to blocks.
{Scand_stage1_str}

Task:
- From the listed candidate blocks, choose at most 20 blocks that are MOST important for determining whether the vulnerability is present.
- Focus on blocks that:
  * Process or sanitize untrusted input,
  * Implement or modify the vulnerable behavior,
  * Implement or modify the fix behavior, or
  * Are directly involved in the critical data/control flow.
- Ignore blocks that only contain tests unrelated to the vulnerability, simple getters/setters, or trivial helpers.

Output format (JSON ONLY, no comments, no extra text):
{{
  "important_ids": ["<block_id_1>", "<block_id_2>", "..."]
}}
""".strip()

    stage1_prompt = stage1_template.format(
        desc=vuln_info.desc,
        pattern_json=pattern_json,
        Bvref_brief=Bvref_brief,
        Scand_stage1_str=Scand_stage1_str,
    )

    stage1_raw = llm(stage1_prompt)

    important_ids: Set[str] = set()
    try:
        stage1_data = json.loads(stage1_raw)
        if isinstance(stage1_data, dict):
            ids = stage1_data.get("important_ids") or []
            if isinstance(ids, list):
                important_ids = {str(x) for x in ids}
    except Exception:
        important_ids = set()

    # Stage1 失败兜底：拿优先级最高的前 5 个块当作“重要”
    if not important_ids:
        for b in _prioritize_blocks(Scand)[:5]:
            important_ids.add(b.id)

    # ---------- Stage 2：构造最终判定用的 Scand 字符串 ----------
    # 重要块：全文；其他块：精简 snippet
    def _make_stage2_scand(blocks: List[CodeBlock],
                           important: Set[str],
                           max_blocks: int = 60,
                           brief_width: int = 220) -> str:
        blocks = _prioritize_blocks(blocks)
        parts = []
        for b in blocks[:max_blocks]:
            base = os.path.basename(b.file_path or "")
            header = f"[{base}:{b.start_line}-{b.end_line}]"
            if b.id in important:
                # 重要块：给完整内容（尽量让模型看到完整函数）
                snippet = b.content or ""
            else:
                content = b.content or ""
                snippet = _shorten(
                    content.replace("\n", " "),
                    width=brief_width,
                    placeholder="...",
                )
            parts.append(f"{header} {snippet}")
        return "\n".join(parts)

    Scand_str = _make_stage2_scand(Scand, important_ids, max_blocks=60, brief_width=220)

    # ---------- 最终判定 Prompt（Stage 2） ----------
    template = """
You are an expert in software vulnerabilities.

Goal:
Decide whether a known vulnerability reappears in a target project.

Given:
1) Dv (official vulnerability description):
{desc}

2) Pv (patch diff, for context only):
{patch_diff}

3) Reference code blocks from vulnerable and fixed versions (Bv_ref):
Each line shows a code region from the original vulnerable and fixed projects.
These illustrate how the vulnerability manifests and how it was fixed.
{Bvref_str}

4) Semantic patterns (already reconstructed from Bv_ref):
{pattern_json}

5) Candidate code blocks in the TARGET project (Scand):
IMPORTANT:
  - Some blocks (the most relevant ones) are shown with FULL source code.
  - Other blocks are shown as brief snippets.
Use all of them to reason about whether the vulnerability reappears.
{Scand_str}

6) Global signals in the TARGET project (pre-computed):
- has_DecodingException class: {has_decoding_exception}
- has_isPayloadValid helper: {has_is_payload_valid}

Decision rule:
- Treat the Vuln-Pattern and Safe-Pattern as semantic guidance, not as strict syntactic templates. When comparing, focus on whether the TARGET project has code that is functionally equivalent (or very similar in risk) to the vulnerable behavior or to the fix, even if the implementation details differ.
- The vulnerability reappears (answer YES) if, based on all available evidence:
  * There exists at least one realistic execution path where untrusted input can reach code that is semantically consistent with the Vuln-Pattern (e.g., deserialization, parsing, or file/command operations without adequate validation), AND
  * The TARGET project does NOT implement protection that is clearly equivalent in effect to the Safe-Pattern (e.g., DecodingException, isPayloadValid, or other explicit validation/defense mechanisms), OR such protection is present but obviously incomplete, misused, or bypassable in the relevant paths.
- Answer NO if, considering the code and patterns as a whole:
  * The vulnerable behavior is clearly absent (e.g., the risky operation or dataflow is removed or fundamentally changed), OR
  * The TARGET project implements effective mitigations that are semantically equivalent to the Safe-Pattern (even if the names or exact structure differ), and you do not see any alternative path that still behaves like the Vuln-Pattern.
- When evidence is mixed or partial (for example, some hints of similar behavior but no clear dataflow from untrusted input, or mitigations that appear mostly but not obviously sufficient), you should make a best-effort expert judgment:
  * Weigh how likely it is that a realistic exploit path still exists, given the available code blocks.
  * Choose the more likely answer (YES or NO) and reflect your uncertainty in the confidence score.

Output format:
Line 1: YES or NO
Line 2: CONFIDENCE: <a float between 0 and 1>
Line 3+: Short explanation (<= 8 sentences)

Do NOT output JSON.
Do NOT use markdown code fences.
Plain text only.
""".strip()

    Bvref_str = _blocks_to_brief(Bvref, limit=20, width=260)

    prompt = template.format(
        desc=vuln_info.desc,
        patch_diff=vuln_info.patch_diff,
        pattern_json=pattern_json,
        Bvref_str=Bvref_str,
        Scand_str=Scand_str,
        has_decoding_exception=has_decoding_exception,
        has_is_payload_valid=has_is_payload_valid,
    )

    # print(prompt) # 调试用
    # exit()

    raw = llm(prompt)
    lines = [ln for ln in raw.splitlines() if ln.strip()]

    if not lines:
        return PredictionResult(
            has_vuln=False,
            confidence=0.0,
            raw_reasoning="LLM returned empty response.",
        )

    first = lines[0].strip().upper()
    has_vuln = first.startswith("Y")  # YES / Yes / yes 都认作 True

    conf = 0.5
    if len(lines) >= 2:
        m = re.search(r"([01](?:\.\d+)?)", lines[1])
        if m:
            try:
                val = float(m.group(1))
                conf = max(0.0, min(1.0, val))
            except Exception:
                pass

    reason = "\n".join(lines[2:]) if len(lines) > 2 else "\n".join(lines)

    return PredictionResult(
        has_vuln=has_vuln,
        confidence=conf,
        raw_reasoning=reason,
    )
