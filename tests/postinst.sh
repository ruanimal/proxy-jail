#!/usr/bin/env bash
# Exercise a scratch-only text copy of postinst, with real visudo validation.
# No mount, chroot, or access to the host's sudoers policy is needed.
set -euo pipefail
umask 022

if [[ $(id -u) != 0 ]]; then
    if ! command -v unshare >/dev/null ||
        ! unshare --user --map-root-user -- /bin/true 2>/dev/null; then
        echo 'SKIP: root or an available unprivileged user namespace is required' >&2
        exit 77
    fi
    exec unshare --user --map-root-user -- bash "$0" "$@"
fi
if [[ ! -x /usr/sbin/visudo ]]; then
    echo 'SKIP: /usr/sbin/visudo is required' >&2
    exit 77
fi

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_script=$repo/debian/postinst
suite=$(mktemp -d "${TMPDIR:-/tmp}/proxy-jail-postinst.XXXXXX")
trap 'rm -rf -- "$suite"' EXIT
passed=0

fail() {
    echo "FAIL: $*" >&2
    if [[ -f ${case_dir:-}/output ]]; then
        cat -- "$case_dir/output" >&2
    fi
    exit 1
}

ok() {
    passed=$((passed + 1))
    printf 'ok %d - %s\n' "$passed" "$1"
}

# This wrapper enforces validation-before-replacement and candidate metadata.
# Only a scratch copy substitutes this absolute path for /usr/sbin/visudo.
cat > "$suite/visudo" <<'EOF'
#!/bin/sh
set -eu
[ "$#" = 3 ] && [ "$1" = -c ] && [ "$2" = -f ] || exit 91
case "$3" in */proxy-jail.??????) ;; *) exit 92 ;; esac
dir=${3%/*}
[ "$(stat -c '%u:%g:%a' -- "$3")" = '0:0:440' ] || exit 93
if [ -f "$dir/.original" ]; then
    cmp -s -- "$dir/.original" "$dir/proxy-jail" || exit 94
else
    [ ! -e "$dir/proxy-jail" ] && [ ! -L "$dir/proxy-jail" ] || exit 95
fi
printf '%s\n' "$3" > "$dir/.checked"
[ ! -e "$dir/.reject-visudo" ] || exit 96
exec /usr/sbin/visudo "$@"
EOF
chmod 0755 "$suite/visudo"

escape_sed() {
    printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
}

new_case() {
    case_dir=$suite/$1
    sudoers_dir=$case_dir/etc/sudoers.d
    file=$sudoers_dir/proxy-jail
    script=$case_dir/postinst
    mkdir -p -- "$sudoers_dir"
    chmod 0755 "$sudoers_dir"
    # Fail closed if production stops using the fixed, non-overridable path.
    grep -qxF 'SUDOERS_FILE="/etc/sudoers.d/proxy-jail"' "$source_script" ||
        fail 'production sudoers path is not the expected constant'
    sed -e "s|/etc/sudoers.d/proxy-jail|$(escape_sed "$file")|g" \
        -e "s|/usr/sbin/visudo|$(escape_sed "$suite/visudo")|g" \
        "$source_script" > "$script"
    grep -qxF "SUDOERS_FILE=\"$file\"" "$script" || fail 'scratch path substitution failed'
    sh -n "$script" || fail 'scratch postinst has invalid shell syntax'
}

configure() {
    rm -f -- "$sudoers_dir/.original" "$sudoers_dir/.checked"
    if [[ -f $file && ! -L $file ]]; then
        cp -- "$file" "$sudoers_dir/.original" || fail 'cannot snapshot policy'
    fi
    sh "$script" configure > "$case_dir/output" 2>&1
}

expect_success() {
    if ! configure; then
        fail 'configure unexpectedly failed'
    fi
    [[ -f $sudoers_dir/.checked ]] || fail 'visudo was not called'
    [[ $(stat -c '%u:%g:%a' -- "$file") == 0:0:440 ]] || fail 'incorrect installed metadata'
    local candidates=("$file".??????)
    [[ ! -e ${candidates[0]} ]] || fail 'temporary candidate leaked'
}

expect_failure() {
    if configure; then
        fail 'configure unexpectedly succeeded'
    fi
    local candidates=("$file".??????)
    [[ ! -e ${candidates[0]} ]] || fail 'temporary candidate leaked on failure'
}

append_defaults() {
    printf '%s\n' \
        'Defaults!/usr/bin/proxy-jail env_reset' \
        'Defaults!/usr/bin/proxy-jail env_keep += "PROXY_JAIL_APP_ENV"'
}

rule='%sudo ALL=(root) NOPASSWD: NOSETENV: /usr/bin/proxy-jail'
new_case fresh
expect_success
cat > "$case_dir/expected" <<'EOF'
# Allow members of group sudo to execute only the installed proxy-jail command.
# NOSETENV forbids -E and environment assignments that bypass sudo filtering.
%sudo ALL=(root) NOPASSWD: NOSETENV: /usr/bin/proxy-jail
EOF
append_defaults >> "$case_dir/expected"
cmp -s -- "$case_dir/expected" "$file" || fail 'incorrect new-install policy'
if grep -Eq '^Defaults[[:space:]]+env_keep' "$file"; then
    fail 'new install introduced global env_keep'
fi
ok 'new install: sudo group, NOSETENV, command-scoped environment, root:root 0440'
cp -- "$file" "$case_dir/before"
expect_success
cmp -s -- "$case_dir/before" "$file" || fail 'fresh-install retry is not idempotent'
ok 'new-install retry is byte-idempotent'

legacy_rules=(
    'ALL ALL=(root) NOPASSWD: /usr/bin/proxy-jail'
    'ALL ALL=(root) NOPASSWD: SETENV: /usr/bin/proxy-jail'
    '%sudo ALL=(root) NOPASSWD: /usr/bin/proxy-jail'
    '%sudo ALL=(root) NOPASSWD: SETENV: /usr/bin/proxy-jail'
)
for i in "${!legacy_rules[@]}"; do
    new_case "legacy-$i"
    printf '# package policy\n%s\n' "${legacy_rules[$i]}" > "$file"
    chmod 0644 "$file"
    old_inode=$(stat -c '%i' -- "$file")
    expect_success
    [[ $(stat -c '%i' -- "$file") != "$old_inode" ]] || fail 'upgrade did not replace the original inode'
    { printf '# package policy\n%s\n' "$rule"; append_defaults; } > "$case_dir/expected"
    cmp -s -- "$case_dir/expected" "$file" || fail "incorrect migration: ${legacy_rules[$i]}"
    cp -- "$file" "$case_dir/before"
    expect_success
    cmp -s -- "$case_dir/before" "$file" || fail 'upgrade retry is not idempotent'
    ok "canonical migration and retry: ${legacy_rules[$i]}"
done

new_case customized
cat > "$case_dir/custom" <<'EOF'
# Administrator policy: preserve every line, including intentional SETENV.
Defaults env_keep += "SITE_TOKEN"
Defaults env_delete += "LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH PERL5LIB RUBYLIB NODE_PATH LUA_PATH LUA_CPATH JAVA_TOOL_OPTIONS"
Defaults!/usr/bin/proxy-jail !env_reset
alice ALL=(root) NOPASSWD: SETENV: /usr/bin/proxy-jail
%deploy ALL=(root) NOPASSWD: /usr/bin/proxy-jail
ALL ALL=(root) PASSWD: /usr/bin/proxy-jail
ALL ALL=(ALL) NOPASSWD: /usr/bin/proxy-jail
ALL ALL=(root) NOPASSWD: SETENV: /opt/proxy-jail
ALL ALL=(root) NOPASSWD: SETENV: /usr/bin/proxy-jail, /usr/bin/true
ALL ALL=(root) NOPASSWD: SETENV: /usr/bin/proxy-jail # local annotation
ALL  ALL=(root) NOPASSWD: SETENV: /usr/bin/proxy-jail
alice, \
%sudo ALL=(root) NOPASSWD: SETENV: /usr/bin/proxy-jail
EOF
cp -- "$case_dir/custom" "$file"
printf '%s\n' "${legacy_rules[1]}" >> "$file"
chmod 0440 "$file"
expect_success
{ cat -- "$case_dir/custom"; printf '%s\n' "$rule"; append_defaults; } > "$case_dir/expected"
cmp -s -- "$case_dir/expected" "$file" || fail 'administrator customization was altered'
ok 'mixed package/admin rules: only the exact canonical package rule changes'

new_case user-specific
printf '%s\n' 'alice ALL=(root) NOPASSWD: /usr/bin/proxy-jail' > "$file"
cp -- "$file" "$case_dir/expected"
append_defaults >> "$case_dir/expected"
expect_success
cmp -s -- "$case_dir/expected" "$file" || fail 'user-specific policy was broadened'
if grep -q '^%sudo ' "$file"; then
    fail 'custom-only policy gained a sudo-group grant'
fi
ok 'user-specific custom-only policy never gains sudo-group authorization'

new_case empty
: > "$file"
expect_success
append_defaults > "$case_dir/expected"
cmp -s -- "$case_dir/expected" "$file" || fail 'empty custom policy gained authorization'
ok 'existing empty policy never gains authorization'

new_case defaults
{
    append_defaults
    printf '%s\n' '# retain this comment' 'Defaults!/usr/bin/proxy-jail !env_reset' "$rule"
    append_defaults
} > "$file"
expect_success
{
    printf '%s\n' '# retain this comment' 'Defaults!/usr/bin/proxy-jail !env_reset' "$rule"
    append_defaults
} > "$case_dir/expected"
cmp -s -- "$case_dir/expected" "$file" || fail 'command Defaults were not normalized at the end'
cp -- "$file" "$case_dir/before"
expect_success
cmp -s -- "$case_dir/before" "$file" || fail 'Defaults normalization is not idempotent'
ok 'command Defaults deduplicate, follow legacy !env_reset, and remain idempotent'

new_case rejected-upgrade
printf '%s\n' "${legacy_rules[1]}" > "$file"
chmod 0600 "$file"
cp -- "$file" "$case_dir/before"
metadata=$(stat -c '%i:%u:%g:%a' -- "$file")
: > "$sudoers_dir/.reject-visudo"
expect_failure
[[ -f $sudoers_dir/.checked ]] || fail 'failure did not reach visudo'
cmp -s -- "$case_dir/before" "$file" || fail 'visudo failure lost the original policy'
[[ $(stat -c '%i:%u:%g:%a' -- "$file") == "$metadata" ]] || fail 'visudo failure changed original metadata'
ok 'forced visudo failure retains original bytes, inode, owner and mode'

new_case rejected-fresh
: > "$sudoers_dir/.reject-visudo"
expect_failure
[[ -f $sudoers_dir/.checked ]] || fail 'fresh failure did not reach visudo'
[[ ! -e $file && ! -L $file ]] || fail 'rejected fresh install left a policy'
ok 'forced visudo failure on fresh install leaves no policy'

new_case syntax-error
printf '%s\n' 'this is not valid sudoers syntax !!!' > "$file"
cp -- "$file" "$case_dir/before"
metadata=$(stat -c '%i:%u:%g:%a' -- "$file")
expect_failure
[[ -f $sudoers_dir/.checked ]] || fail 'invalid syntax did not reach real visudo'
cmp -s -- "$case_dir/before" "$file" || fail 'real visudo failure changed original content'
[[ $(stat -c '%i:%u:%g:%a' -- "$file") == "$metadata" ]] || fail 'real visudo failure changed original metadata'
ok 'real visudo syntax rejection leaves the original intact'

for kind in symlink dangling; do
    new_case "$kind"
    target=$case_dir/target
    if [[ $kind == symlink ]]; then
        printf '%s\n' 'do not alter this target' > "$target"
        chmod 0600 "$target"
        cp -- "$target" "$case_dir/before"
        metadata=$(stat -c '%i:%u:%g:%a' -- "$target")
    fi
    ln -s -- "$target" "$file"
    expect_failure
    [[ -L $file && $(readlink -- "$file") == "$target" ]] || fail 'symlink was replaced'
    if [[ $kind == symlink ]]; then
        cmp -s -- "$case_dir/before" "$target" || fail 'symlink target was changed'
        [[ $(stat -c '%i:%u:%g:%a' -- "$target") == "$metadata" ]] || fail 'symlink target metadata changed'
    else
        [[ ! -e $target ]] || fail 'dangling symlink target was created'
    fi
    ok "reject $kind without following or replacing it"
done

for mode in 0460 0442 0666 4440; do
    new_case "unsafe-mode-$mode"
    printf '%s\n' "${legacy_rules[0]}" > "$file"
    chmod "$mode" "$file"
    cp -- "$file" "$case_dir/before"
    metadata=$(stat -c '%i:%u:%g:%a' -- "$file")
    expect_failure
    cmp -s -- "$case_dir/before" "$file" || fail 'unsafe policy content changed'
    [[ $(stat -c '%i:%u:%g:%a' -- "$file") == "$metadata" ]] || fail 'unsafe policy metadata changed'
    ok "reject unsafe existing mode $mode"
done

new_case hardlink
printf '%s\n' "${legacy_rules[0]}" > "$file"
ln -- "$file" "$case_dir/other-link"
metadata=$(stat -c '%i:%h:%u:%g:%a' -- "$file")
expect_failure
[[ $(stat -c '%i:%h:%u:%g:%a' -- "$file") == "$metadata" ]] || fail 'hard-linked file changed'
[[ $(cat -- "$case_dir/other-link") == "${legacy_rules[0]}" ]] || fail 'other hard link changed'
ok 'reject hard-linked policy'

for kind in directory fifo; do
    new_case "nonregular-$kind"
    if [[ $kind == directory ]]; then mkdir -- "$file"; else mkfifo -- "$file"; fi
    metadata=$(stat -c '%i:%F:%a' -- "$file")
    expect_failure
    [[ $(stat -c '%i:%F:%a' -- "$file") == "$metadata" ]] || fail 'nonregular original changed'
    ok "reject nonregular policy: $kind"
done

new_case symlink-directory
mv -- "$sudoers_dir" "$case_dir/real-directory"
ln -s -- "$case_dir/real-directory" "$sudoers_dir"
expect_failure
[[ -L $sudoers_dir && ! -e $file ]] || fail 'symlink directory was followed or replaced'
ok 'reject symlinked sudoers directory'

new_case writable-directory
chmod 0777 "$sudoers_dir"
expect_failure
[[ ! -e $file ]] || fail 'writable directory gained a policy'
ok 'reject untrusted writable sudoers directory'

# A second namespace maps the fixture owner to a non-root uid, without chowning
# anything on the host. This exercises the production root-ownership check.
if command -v unshare >/dev/null &&
    unshare --user --map-user=1 --map-group=1 -- /bin/true 2>/dev/null; then
    new_case nonroot-owner
    printf '%s\n' "${legacy_rules[0]}" > "$file"
    cp -- "$file" "$case_dir/before"
    if unshare --user --map-user=1 --map-group=1 -- sh "$script" configure > "$case_dir/output" 2>&1; then
        fail 'non-root ownership was accepted'
    fi
    grep -q 'must be owned by root:root' "$case_dir/output" || fail 'ownership check was not reached'
    cmp -s -- "$case_dir/before" "$file" || fail 'non-root-owned policy changed'
    ok 'reject non-root-owned path in a nested user namespace'
else
    echo 'SKIP: nested user namespace unavailable for non-root-owner case'
fi

printf 'PASS: %d postinst checks (scratch files only; real visudo, no host sudoers writes)\n' "$passed"
