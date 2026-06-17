#!/usr/bin/env nu
# Install/update the locally built gp-saml-gui conda package into a global pixi environment.

# Remove existing global environment if present
try { pixi global uninstall gp-saml-gui out+err>| ignore }

# Find the most recently built conda package
let pkg = (
    ls output/linux-64/gp-saml-gui-*.conda
    | sort-by modified --reverse
    | first
    | get name
)

print $"Installing ($pkg)..."
pixi global install --path $pkg
