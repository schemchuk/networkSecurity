#!/usr/bin/env bash
# labshell rcfile — logs every executed command to commands.jsonl.
# This file is sourced by bash via --rcfile; do not execute directly.

if [ -f "$HOME/.bashrc" ]; then
    source "$HOME/.bashrc"
fi

# Avoid logging the logger invocation or internal helpers.
AILAB_LAST_CMD=""

_ailab_preexec() {
    local cmd
    cmd="$BASH_COMMAND"
    # Skip logger calls, internal functions, and the prompt command itself.
    case "$cmd" in
        *logcmd.py*|_ailab_*|"\[") return ;;
    esac
    AILAB_LAST_CMD="$cmd"
}

_ailab_precmd() {
    local exit_code=$?
    if [ -n "$AILAB_LAST_CMD" ]; then
        python "$AILAB_SCRIPTS/logcmd.py" \
            --file "$AILAB_CMDLOG" \
            --cmd "$AILAB_LAST_CMD" \
            --exit "$exit_code" \
            --cwd "$PWD" >/dev/null 2>&1
    fi
    AILAB_LAST_CMD=""
}

trap '_ailab_preexec' DEBUG
PROMPT_COMMAND='_ailab_precmd'

export PS1="(lab:$AILAB_RUN_ID) $PS1"
