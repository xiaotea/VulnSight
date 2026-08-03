import argparse
from vulnsight.sever import VulnSight
from vulnsight.types import VulnKnowledge


import os
from openai import OpenAI

# 用环境变量保存你的 LLM_API_KEY
LLM_API_KEY = os.getenv("LLM_API_KEY")

client = OpenAI(
    api_key=LLM_API_KEY,
    base_url="https://api.deepseek.com",
)

def my_llm(prompt: str) -> str:
    """
    调用 DeepSeek Chat 模型，返回纯文本结果字符串。
    """
    if not LLM_API_KEY:
        raise RuntimeError("请先在环境变量中设置 LLM_API_KEY")

    resp = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": "You are a helpful vulnerability analysis assistant."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
    )
    # VulnSight 期待的是一个纯文本字符串
    return resp.choices[0].message.content


def main():
    parser = argparse.ArgumentParser(description="VulnSight: 通用漏洞存在性语义验证工具")
    parser.add_argument("--vuln-id", type=str, required=True, help="漏洞 ID，如 CVE-XXXX-YYYY")
    parser.add_argument("--patch", type=str, required=True, help="补丁 diff 文件路径 (.patch)")
    parser.add_argument("--desc", type=str, required=True, help="漏洞描述文本，或描述文件路径")
    parser.add_argument("--vuln-root", type=str, required=True, help="漏洞版本代码目录 Cv")
    parser.add_argument("--fix-root", type=str, required=True, help="修复版本代码目录 Cv_fix")
    parser.add_argument("--target-root", type=str, required=True, help="待检测代码目录 Ct")
    parser.add_argument("--lang", type=str, default="", help="语言提示，如 python, c, cpp")
    args = parser.parse_args()

    with open(args.patch, "r", encoding="utf-8", errors="ignore") as f:
        patch_diff = f.read()

    desc = args.desc
    # 如果 desc 看起来像文件路径且以 .txt/.md 结尾，则尝试读文件
    import os
    if (desc.endswith(".txt") or desc.endswith(".md")) and os.path.exists(desc):
        with open(desc, "r", encoding="utf-8", errors="ignore") as f:
            desc = f.read()

    vuln = VulnKnowledge(
        vuln_id=args.vuln_id,
        desc=desc,
        patch_diff=patch_diff,
        vuln_proj_root=args.vuln_root,
        fix_proj_root=args.fix_root,
    )

    vulnsight = VulnSight(
        llm=my_llm,
        language_hint=args.lang,
    )

    result = vulnsight.verify(
        target_root=args.target_root,
        vuln=vuln,
    )

    print("=== VulnSight Result ===")
    print("Vulnerability ID:", args.vuln_id)
    print("Target project:", args.target_root)
    print("Has vulnerability:", result.has_vuln)
    print("Confidence:", result.confidence)
    print("Reasoning:\n", result.raw_reasoning)


if __name__ == "__main__":
    main()
