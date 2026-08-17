#!/bin/sh

set -eu

if [ "$#" -lt 3 ]; then
	printf 'usage: %s OUTPUT INPUT INPUT [...]\n' "$0" >&2
	exit 2
fi

output=$1
shift

for profile in "$@"; do
	if [ ! -f "$profile" ]; then
		printf 'coverage profile does not exist: %s\n' "$profile" >&2
		exit 1
	fi
done

temporary=$(mktemp "${TMPDIR:-/tmp}/goauth-coverage.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM

awk '
	FNR == 1 && /^mode:/ {
		if (mode == "") {
			mode = $0
		} else if (mode != $0) {
			printf "coverage modes do not match: %s and %s\n", mode, $0 > "/dev/stderr"
			exit 2
		}
		next
	}
	{
		key = $1 SUBSEP $2
		if (!(key in seen)) {
			seen[key] = ++entries
			position[entries] = $1
			statements[entries] = $2
		}
		hits[key] += $3
	}
	END {
		if (mode == "") {
			print "coverage profile mode is missing" > "/dev/stderr"
			exit 2
		}
		print mode
		for (entry = 1; entry <= entries; entry++) {
			key = position[entry] SUBSEP statements[entry]
			printf "%s %s %d\n", position[entry], statements[entry], hits[key]
		}
	}
' "$@" > "$temporary"

mv "$temporary" "$output"
trap - EXIT HUP INT TERM
