#!/usr/bin/env sh
set -eu

outfile=${1:-merged.c}

# temp files; cleaned on exit
tmp_merge=$(mktemp "${outfile}.merge.XXXXXX") || { echo "mktemp failed" >&2; exit 1; }
tmp_dedup=$(mktemp "${outfile}.dedup.XXXXXX") || { rm -f "$tmp_merge"; echo "mktemp failed" >&2; exit 1; }
trap 'rm -f "$tmp_merge" "$tmp_dedup"' EXIT HUP INT TERM

# ---- 1) Find & merge all .c files (exclude outfile iff it exists) ----
if [ -e "$outfile" ]; then
  # Exclude current outfile so we don't self-append
  find . -type f -name '*.c' ! -samefile "$outfile" -print0
else
  find . -type f -name '*.c' -print0
fi \
| sort -z \
| xargs -0 -I{} sh -c '
  f=$1; out=$2
  printf "/* ===== %s ===== */\n// line 1 \"%s\"\n" "$f" "$f" >> "$out"
  cat "$f" >> "$out"
  printf "\n" >> "$out"
' sh {} "$tmp_merge"

# ---- 2) Deduplicate #include lines (portable awk) ----
awk '
  # trim leading spaces/tabs
  function ltrim(s){ sub(/^[ \t]+/,"",s); return s }
  # return <...> or "..." include token, else ""
  function include_key(line,   s,qpos,rpos){
    s=ltrim(line)
    if (substr(s,1,1)!="#") return ""
    s=ltrim(substr(s,2))
    if (substr(s,1,7)!="include") return ""
    s=ltrim(substr(s,8))
    if (substr(s,1,1)=="<") { rpos=index(s,">"); if(rpos) return substr(s,1,rpos); else return "" }
    if (substr(s,1,1)=="\""){ qpos=index(substr(s,2),"\""); if(qpos) return substr(s,1,qpos+1); else return "" }
    return ""
  }
  {
    k=include_key($0)
    if (k!="") {
      if (k in seen) next
      seen[k]=1
    }
    print
  }
' "$tmp_merge" > "$tmp_dedup"

# ---- 3) Publish atomically ----
mv -f -- "$tmp_dedup" "$outfile"
rm -rf "$tmp_merge"
trap - EXIT
echo "Wrote $outfile"
