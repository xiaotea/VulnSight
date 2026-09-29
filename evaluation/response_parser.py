"""Decision parser preserved from the original Python scoring script."""
import re


def explicit_decisions(answer):
    """Every line that states a bare YES/NO verdict; last one wins."""
    text = answer.rsplit("</think>", 1)[-1].strip()
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    return [value.upper() for value in re.findall(
        r"(?im)^[ \t]*(?:(?:Line\s*1|Answer):[ \t]*)?(YES|NO)"
        r"(?:[ \t]*:[ \t]*CONFIDENCE[ \t]*:[ \t]*[01](?:\.\d+)?)?[.!]?[ \t]*$",
        text)]


def parse_answer(answer):
    """The verdict of one prediction, or None when it cannot be read safely.

    Only explicit decisions count; YES/NO mentioned inside explanatory prose is
    ignored.  A prose conclusion is accepted solely as 'Therefore, YES/NO'
    directly above a CONFIDENCE line.
    """
    if not isinstance(answer, str) or not answer.strip():
        return None
    matches = explicit_decisions(answer)
    if matches:
        return matches[-1]
    text = re.sub(r"```.*?```", "", answer.rsplit("</think>", 1)[-1], flags=re.S)
    matches = re.findall(
        r"(?im)^[ \t]*(?:\*[ \t]*)?Therefore,[ \t]*(YES|NO)[.!]?[ \t]*\r?\n"
        r"\s*CONFIDENCE[ \t]*:", text)
    return matches[-1].upper() if matches else None


