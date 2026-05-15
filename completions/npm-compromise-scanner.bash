# bash completion for npm-compromise-scanner
#
# Install:
#   source /path/to/completions/npm-compromise-scanner.bash   # from ~/.bashrc
# or copy into your bash completion directory:
#   macOS (Homebrew):  $(brew --prefix)/etc/bash_completion.d/
#   Linux:             /etc/bash_completion.d/

_npm_compromise_scanner() {
  local cur prev opts
  cur="${COMP_WORDS[COMP_CWORD]}"
  opts="--skip-node-modules --json --no-color --help --version"

  # Complete option flags.
  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    return 0
  fi

  # First positional = directory to scan; subsequent = CSV / files.
  local nonflag=0 i
  for (( i = 1; i < COMP_CWORD; i++ )); do
    [[ "${COMP_WORDS[i]}" != -* ]] && (( nonflag++ ))
  done
  if (( nonflag == 0 )); then
    COMPREPLY=( $(compgen -d -- "$cur") )
  else
    COMPREPLY=( $(compgen -f -- "$cur") )
  fi
}

complete -o filenames -F _npm_compromise_scanner npm-compromise-scanner
