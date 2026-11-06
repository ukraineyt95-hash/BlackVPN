#!/usr/bin/env python3
"""Опубликовать ошибки компиляции из лога cargo как отдельный check run.

Зачем: логи шага лежат в blob storage, и не из всякой сети (в том числе из
песочницы агента) их можно скачать — `gh run view --log-failed` отдаёт EOF.
Check run читается через обычный API `api.github.com`, поэтому ошибки видны
откуда угодно.

Использование:
    python3 report-cargo-errors.py <cargo.log> <head_sha>

Переменные окружения: GITHUB_TOKEN, GITHUB_REPOSITORY.
Скрипт никогда не валит шаг: диагностика не должна прятать настоящую ошибку.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

ANSI = re.compile(r"\x1b\[[0-9;]*m")
MAX_TEXT = 60000
CONTEXT = 10


def read_blocks(path):
    """Вырезать из лога блоки, начинающиеся со строки `error`."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = [ANSI.sub("", line.rstrip("\n")) for line in fh]

    blocks, current = [], []
    left = 0
    for line in lines:
        if line.startswith("error"):
            if current:
                blocks.append("\n".join(current))
            current, left = [line], CONTEXT
        elif left > 0:
            current.append(line)
            left -= 1
        elif line.strip() and current:
            # Пустая строка/шум завершают блок.
            blocks.append("\n".join(current))
            current = []
    if current:
        blocks.append("\n".join(current))

    # Отбрасываем финальное «could not compile» — оно ничего не добавляет.
    blocks = [b for b in blocks if "could not compile" not in b.splitlines()[0]]
    return blocks, lines


def build_payload(path, sha):
    blocks, lines = read_blocks(path)
    if blocks:
        text = "\n\n".join(blocks)
        title = "cargo test failed"
    else:
        text = "\n".join(lines[-150:])
        title = "cargo test failed (no `error:` lines found)"

    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT] + "\n… (обрезано)"

    summary = blocks[0].splitlines()[0] if blocks else title
    return {
        "name": "cargo-test-diagnostics",
        "head_sha": sha,
        "status": "completed",
        "conclusion": "failure",
        "output": {
            "title": title,
            "summary": summary[:600],
            "text": text,
            "annotations": [],
        },
    }


def main():
    if len(sys.argv) < 3:
        print("usage: report-cargo-errors.py <cargo.log> <head_sha>", file=sys.stderr)
        return 0

    log_path, sha = sys.argv[1], sys.argv[2]
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not (token and repo and os.path.isfile(log_path)):
        print("диагностика: нет токена/репозитория или лога — пропускаю", file=sys.stderr)
        return 0

    payload = json.dumps(build_payload(log_path, sha)).encode()
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/check-runs",
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            print(f"диагностика: check run создан ({resp.status})", file=sys.stderr)
    except urllib.error.HTTPError as exc:
        print(f"диагностика: не удалось создать check run ({exc.code})", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 - диагностика не должна валить шаг
        print(f"диагностика: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
