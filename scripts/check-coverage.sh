#!/bin/sh

set -eu

if [ "$#" -lt 2 ]; then
	printf 'usage: %s PROFILE PACKAGE=THRESHOLD [...]\n' "$0" >&2
	exit 2
fi

profile=$1
shift

if [ ! -f "$profile" ]; then
	printf 'coverage profile does not exist: %s\n' "$profile" >&2
	exit 1
fi

module=$(go list -m)
failed=0

for requirement in "$@"; do
	package=${requirement%=*}
	threshold=${requirement##*=}
	if [ "$package" = "$requirement" ]; then
		printf 'invalid coverage requirement: %s\n' "$requirement" >&2
		exit 2
	fi
	if [ "$package" = "." ]; then
		expected=$module
	else
		expected=$module/$package
	fi

	if ! awk -v expected="$expected" -v threshold="$threshold" '
		NR == 1 { next }
		{
			location = $1
			sub(":[0-9].*$", "", location)
			directory = location
			sub("/[^/]+$", "", directory)
			if (directory != expected) {
				next
			}
			total += $2
			if ($3 > 0) {
				covered += $2
			}
		}
		END {
			if (total == 0) {
				printf "coverage: no statements found for %s\n", expected > "/dev/stderr"
				exit 2
			}
			percentage = 100 * covered / total
			printf "coverage: %s %.1f%% (required %.1f%%)\n", expected, percentage, threshold
			if (percentage + 0.000001 < threshold) {
				exit 1
			}
		}
	' "$profile"; then
		failed=1
	fi
done

exit "$failed"
