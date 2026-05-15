# fish completion for npm-compromise-scanner
#
# Install:
#   cp completions/npm-compromise-scanner.fish ~/.config/fish/completions/

complete -c npm-compromise-scanner -l skip-node-modules \
  -d 'Scan only manifests/lockfiles, not installed node_modules'
complete -c npm-compromise-scanner -l json \
  -d 'Emit machine-readable JSON to stdout'
complete -c npm-compromise-scanner -l no-color \
  -d 'Disable colored output'
complete -c npm-compromise-scanner -s h -l help -d 'Show help'
complete -c npm-compromise-scanner -s V -l version -d 'Show version'

# Positional args: fish completes files/directories by default.
