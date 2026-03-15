#!/usr/bin/env bash
# Source Hades-only credentials for GPU experiments
# These are the ONLY secrets Hades needs — no Telegram, no gateway, no Supabase

set -a
[ -f ~/.credentials/hades/huggingface.env ] && source ~/.credentials/hades/huggingface.env
[ -f ~/.credentials/hades/github.env ] && source ~/.credentials/hades/github.env
set +a

echo "Hades credentials loaded:"
echo "  HF_TOKEN: $([ -n "$HF_TOKEN" ] && echo 'set' || echo 'NOT SET — run: echo HF_TOKEN=hf_xxx > ~/.credentials/hades/huggingface.env')"
echo "  GH_TOKEN: $([ -n "$GH_TOKEN" ] && echo 'set' || echo 'NOT SET — run: echo GH_TOKEN=ghp_xxx > ~/.credentials/hades/github.env')"
