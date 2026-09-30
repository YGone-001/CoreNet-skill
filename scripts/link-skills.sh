#!/usr/bin/env bash
# 将本仓库 skills/ 下的技能链接到本地技能发现目录。
# 用法: ./scripts/link-skills.sh [目标目录]
#   默认: ~/.agents/skills (跨工具通用)
#   例:  ./scripts/link-skills.sh ~/.zcode/skills
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
target=${1:-$HOME/.agents/skills}

shopt -s nullglob
skills=("$root"/skills/*/)

if [[ ${#skills[@]} -eq 0 ]]; then
  echo "skills/ 下暂无技能,先运行 ./scripts/new-skill.sh 创建。" >&2
  exit 0
fi

mkdir -p "$target"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) windows=1 ;;
  *) windows=0 ;;
esac

linked=0
for dir in "${skills[@]}"; do
  name=$(basename "$dir")
  [[ -f "$dir/SKILL.md" ]] || continue
  dest="$target/$name"

  if [[ -e "$dest" || -L "$dest" ]]; then
    echo "跳过 $name(目标已存在: $dest)"
    continue
  fi

  if [[ $windows -eq 1 ]]; then
    # 目录 Junction:无需管理员权限;指向仓库内目录,git pull 后自动生效
    cmd //c mklink //J "$(cygpath -w "$dest")" "$(cygpath -w "$dir")" >/dev/null
  else
    ln -s "$dir" "$dest"
  fi
  echo "已链接 $name → $dest"
  linked=$((linked+1))
done

echo "完成:新链接 $linked 个。重启 ZCode 会话后生效。"
