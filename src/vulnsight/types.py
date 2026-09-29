from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple


@dataclass
class CodeSpan:
    file_path: str
    start_line: int
    end_line: int
    language: Optional[str] = None

    def to_brief_str(self) -> str:
        return f"{self.file_path}:{self.start_line}-{self.end_line}"


@dataclass
class VulnPattern:
    """漏洞语义模式 Vuln-Pattern."""
    key_blocks: List[CodeSpan]            # Bv_key
    cause_desc: str                       # Φ_v^cause
    ctrlflow_cond: str                    # Φ_v^CF
    dataflow_cond: str                    # Φ_v^DF
    positive_tests: List[str]             # T_v^+

    def to_prompt_dict(self) -> Dict[str, Any]:
        return {
            "type": "vuln_pattern",
            "cause": self.cause_desc,
            "ctrlflow": self.ctrlflow_cond,
            "dataflow": self.dataflow_cond,
            "key_blocks": [b.to_brief_str() for b in self.key_blocks],
            "positive_tests": self.positive_tests,
        }


@dataclass
class SafePattern:
    """修复语义模式 Safe-Pattern."""
    key_blocks: List[CodeSpan]            # Bvfix-key
    fix_desc: str                         # Φ_v^{fix}
    ctrlflow_fix: str                     # Φ_v^{CF-fix}
    dataflow_fix: str                     # Φ_v^{DF-fix}
    negative_tests: List[str]             # T_v^-

    def to_prompt_dict(self) -> Dict[str, Any]:
        return {
            "type": "safe_pattern",
            "fix": self.fix_desc,
            "ctrlflow_fix": self.ctrlflow_fix,
            "dataflow_fix": self.dataflow_fix,
            "key_blocks": [b.to_brief_str() for b in self.key_blocks],
            "negative_tests": self.negative_tests,
        }


@dataclass
class VulnKnowledge:
    """Iv：与漏洞相关的输入信息."""
    vuln_id: str
    desc: str            # Dv
    patch_diff: str      # Pv
    vuln_proj_root: str  # Cv 根路径
    fix_proj_root: str   # Cv_fix 根路径


@dataclass
class CodeBlock:
    """统一的代码块表示，用于 Bt / Bv / Bvfix / Bvref / Scand."""
    id: str
    file_path: str
    start_line: int
    end_line: int
    content: str
    language: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def span(self) -> CodeSpan:
        return CodeSpan(
            file_path=self.file_path,
            start_line=self.start_line,
            end_line=self.end_line,
            language=self.language,
        )


@dataclass
class CallGraph:
    """简单调用图表示 G=(V,E)."""
    nodes: List[str]
    edges: List[Tuple[str, str]]  # (caller, callee)

    def neighbors(self, node_ids: List[str]) -> List[str]:
        neigh = set()
        for u, v in self.edges:
            if u in node_ids:
                neigh.add(v)
            if v in node_ids:
                neigh.add(u)
        return list(neigh)


@dataclass
class PatternPair:
    vuln_pattern: VulnPattern
    safe_pattern: SafePattern


@dataclass
class PredictionResult:
    has_vuln: bool
    raw_reasoning: str
    confidence: float
