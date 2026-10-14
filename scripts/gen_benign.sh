#!/usr/bin/env bash
# Generates varied, normal IPv4 traffic from this machine so the monitor can record a benign baseline.
# Usage: bash scripts/gen_benign.sh [minutes]   (default 60). Only contacts public, well-known sites.
MIN=${1:-60}; END=$(( $(date +%s) + MIN * 60 ))
SITES=(google.com youtube.com github.com wikipedia.org amazon.in flipkart.com stackoverflow.com reddit.com
  bbc.com thehindu.com ndtv.com timesofindia.indiatimes.com microsoft.com apple.com cloudflare.com
  python.org pypi.org npmjs.com rust-lang.org crates.io docker.com ubuntu.com mozilla.org medium.com
  linkedin.com x.com instagram.com netflix.com spotify.com zomato.com swiggy.com irctc.co.in
  vtu.ac.in dsatm.edu.in w3schools.com geeksforgeeks.org kaggle.com huggingface.co openai.com anthropic.com)
HTTP_ONLY=(neverssl.com example.com httpforever.com)
FILES=(https://proof.ovh.net/files/1Mb.dat https://proof.ovh.net/files/10Mb.dat
  https://www.python.org/ftp/python/3.13.0/Python-3.13.0.tgz https://github.com/git/git/archive/refs/tags/v2.47.0.tar.gz)
C="curl -4 -sL -o /dev/null --max-time 40 -A Mozilla/5.0"
pick() { local a=("$@"); echo "${a[RANDOM % ${#a[@]}]}"; }
n=0
while [ "$(date +%s)" -lt "$END" ]; do
  case $((RANDOM % 10)) in
    0|1|2) $C "https://$(pick "${SITES[@]}")" ;;                                    # one page
    3)     $C "https://$(pick "${SITES[@]}")" "https://$(pick "${SITES[@]}")" ;;    # two pages
    4)     $C "http://$(pick "${HTTP_ONLY[@]}")" ;;                                  # plain HTTP
    5)     getent ahostsv4 "$(pick "${SITES[@]}")" >/dev/null ;;                     # DNS lookups
    6)     $C --limit-rate $((50 + RANDOM % 400))k "$(pick "${FILES[@]}")" ;;        # download / slow stream
    7)     git ls-remote -q https://github.com/$(pick rust-lang/rust python/cpython facebook/react torvalds/linux) HEAD >/dev/null 2>&1 ;;
    8)     for i in 1 2 3 4 5; do $C "https://$(pick "${SITES[@]}")" & done; wait ;; # burst like a page load
    9)     $C "https://api.github.com/repos/$(pick rust-lang/rust python/cpython facebook/react)" ;;  # API call
  esac
  n=$((n + 1)); [ $((n % 20)) -eq 0 ] && echo "$(date +%T) actions: $n"
  sleep $((1 + RANDOM % 6))
done
echo "done: $n actions in $MIN minutes"
