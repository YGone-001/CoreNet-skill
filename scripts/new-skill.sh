#!/usr/bin/env bash
# 创建新技能骨架:./scripts/new-skill.sh <skill-name> ["一句话描述"]
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "用法: $0 <skill-name> [\"一句话描述\"]" >&2
  exit 1
fi

name=$1
description=${2:-"<做什么、什么时候用>"}

if [[ ! "$name" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]]; then
  echo "错误: 技能名必须为小写 kebab-case(字母/数字/连字符,1-64 字符): $name" >&2
  exit 1
fi

root=$(cd "$(dirname "$0")/.." && pwd)
target="$root/skills/$name"

if [[ -e "$target" ]]; then
  echo "错误: skills/$name 已存在" >&2
  exit 1
fi

mkdir -p "$target"
sed -e "s|{{SKILL_NAME}}|$name|g" \
    -e "s|{{SKILL_DESCRIPTION}}|$description|g" \
    "$root/templates/SKILL.template.md" > "$target/SKILL.md"

echo "已创建 skills/$name/SKILL.md"
echo "下一步: 编辑该文件,并在 skills/README.md 索引中登记。"
