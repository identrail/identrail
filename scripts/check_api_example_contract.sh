#!/usr/bin/env bash
set -euo pipefail

readonly openapi_file="docs/openapi-v1.yaml"
readonly -a search_roots=("README.md" "docs" "deploy" "web")

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

readonly component_query_file="${tmp_dir}/component-query-params.tsv"
readonly contract_ops_file="${tmp_dir}/contract-ops.tsv"
readonly contract_query_file="${tmp_dir}/contract-query-params.txt"
readonly examples_file="${tmp_dir}/examples.tsv"

awk '
/^  parameters:/ {
	in_components = 1
	next
}
/^  responses:/ {
	in_components = 0
}
in_components && /^    [A-Za-z0-9_]+:/ {
	name = $1
	sub(/:$/, "", name)
	current = name
	current_in = ""
	next
}
in_components && /^      in: / {
	current_in = $2
	next
}
in_components && /^      name: / && current_in == "query" {
	print current "\t" $2
}
' "${openapi_file}" >"${component_query_file}"

awk '
/^  \// {
	path = $1
	sub(/:$/, "", path)
	next
}
/^    (get|post|put|patch|delete):/ {
	method = toupper($1)
	sub(/:$/, "", method)
	print method "\t" path
}
' "${openapi_file}" >"${contract_ops_file}"

{
	cut -f2 "${component_query_file}"
	awk '
	/- in: query$/ {
		pending_query = 1
		next
	}
	pending_query && /^[[:space:]]+name: / {
		print $2
		pending_query = 0
		next
	}
	/^[[:space:]]+- in: / && $0 !~ /- in: query$/ {
		pending_query = 0
	}
	' "${openapi_file}"
} | sort -u >"${contract_query_file}"

git grep -nI -E '(curl|(^|[`( ])(GET|POST|PUT|PATCH|DELETE)[[:space:]]+/|(^|[`( ])/(v1/|healthz|readyz|metrics|webhooks/github)|https?://[^ ]+/(v1/|healthz|readyz|metrics|webhooks/github))' -- "${search_roots[@]}" ":(exclude)${openapi_file}" \
	>"${tmp_dir}/raw-examples.txt" || true

normalize_path() {
	local path="$1"
	local token=""
	local replacement=""
	path="${path%%[\?#]*}"
	while [[ "${path}" =~ \$\{encodeURIComponent\(([A-Za-z0-9_]+)\)\} ]]; do
		token="${BASH_REMATCH[1]}"
		replacement="{${token}}"
		path="${path/${BASH_REMATCH[0]}/${replacement}}"
	done
	while [[ "${path}" =~ \$\{([A-Za-z0-9_]+)\} ]]; do
		token="${BASH_REMATCH[1],,}"
		replacement="{${token}}"
		path="${path/${BASH_REMATCH[0]}/${replacement}}"
	done
	if [[ "${path}" == *'${'* ]]; then
		path="${path%%\$\{*}"
	fi
	while [[ "${path}" =~ :([A-Za-z0-9_]+) ]]; do
		token="${BASH_REMATCH[1]}"
		replacement="{${token}}"
		path="${path/${BASH_REMATCH[0]}/${replacement}}"
	done
	while [[ "${path}" == *[\`\)\],.\"] ]]; do
		path="${path::-1}"
	done
	if [[ "${path}" != "/" ]]; then
		path="${path%/}"
	fi
	printf '%s\n' "${path}"
}

path_shape() {
	local path="$1"
	while [[ "${path}" =~ \{[^}]+\} ]]; do
		path="${path/${BASH_REMATCH[0]}/{}"
	done
	printf '%s\n' "${path}"
}

extract_query() {
	local raw="$1"
	if [[ "${raw}" != *\?* ]]; then
		printf '\n'
		return
	fi
	local query="${raw#*\?}"
	query="${query%%#*}"
	while [[ "${query}" == *[\`\)\],.\"] ]]; do
		query="${query::-1}"
	done
	printf '%s\n' "${query}"
}

emit_example() {
	local method="$1"
	local raw="$2"
	local source="$3"
	local path
	path="$(normalize_path "${raw}")"
	local query
	query="$(extract_query "${raw}")"
	if [[ -n "${path}" ]]; then
		printf '%s\t%s\t%s\t%s\n' "${method}" "${path}" "${query:--}" "${source}" >>"${examples_file}"
	fi
}

: >"${examples_file}"
while IFS= read -r raw_line; do
	if [[ ! "${raw_line}" =~ ^([^:]+):([0-9]+):(.*)$ ]]; then
		continue
	fi
	source="${BASH_REMATCH[1]}:${BASH_REMATCH[2]}"
	text="${BASH_REMATCH[3]}"

	if [[ "${text}" == *curl* ]]; then
		method="GET"
		if [[ "${text}" =~ (-X|--request)[[:space:]]+(GET|POST|PUT|PATCH|DELETE) ]]; then
			method="${BASH_REMATCH[2]}"
		fi
		if [[ "${text}" =~ (/(v1/[^[:space:]\"\'\`\)]+|healthz|readyz|metrics|webhooks/github[^[:space:]\"\'\`\)]*)) ]]; then
			emit_example "${method}" "${BASH_REMATCH[1]}" "${source}"
		fi
	fi

	remaining="${text}"
	while [[ "${remaining}" =~ (GET|POST|PUT|PATCH|DELETE)[[:space:]]+(\/[A-Za-z0-9_\/:{}?=&.$()!-]+) ]]; do
		emit_example "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${source}"
		remaining="${remaining#*"${BASH_REMATCH[0]}"}"
	done

	remaining="${text}"
	while [[ "${remaining}" =~ (\/(v1\/[A-Za-z0-9_\/:{}?=&.$()!-]+|healthz|readyz|metrics|webhooks/github[A-Za-z0-9_\/:{}?=&.$()!-]*)) ]]; do
		emit_example "PATH" "${BASH_REMATCH[1]}" "${source}"
		remaining="${remaining#*"${BASH_REMATCH[1]}"}"
	done
done <"${tmp_dir}/raw-examples.txt"

sort -u "${examples_file}" -o "${examples_file}"

declare -A valid_ops=()
declare -A valid_paths=()
while IFS=$'\t' read -r method path; do
	shape="$(path_shape "${path}")"
	valid_ops["${method} ${shape}"]=1
	valid_paths["${shape}"]=1
done <"${contract_ops_file}"

declare -A valid_query_params=()
while IFS= read -r name; do
	valid_query_params["${name}"]=1
done <"${contract_query_file}"

fail=0
while IFS=$'\t' read -r method path query source; do
	if [[ "${query}" == "-" ]]; then
		query=""
	fi
	shape="$(path_shape "${path}")"
	if [[ "${method}" == "PATH" ]]; then
		if [[ -z "${valid_paths["${shape}"]+x}" ]]; then
			echo "Unknown API example: ${path} (${source})"
			fail=1
			continue
		fi
	elif [[ -z "${valid_ops["${method} ${shape}"]+x}" ]]; then
		echo "Unknown API example: ${method} ${path} (${source})"
		fail=1
		continue
	fi

	if [[ -z "${query}" ]]; then
		continue
	fi

	IFS='&' read -r -a pairs <<<"${query}"
	for pair in "${pairs[@]}"; do
		param="${pair%%=*}"
		if [[ -z "${param}" ]]; then
			continue
		fi
		if [[ -z "${valid_query_params["${param}"]+x}" ]]; then
			echo "Unknown query parameter '${param}' for ${method} ${path} (${source})"
			fail=1
		fi
	done
done <"${examples_file}"

if [[ "${fail}" -ne 0 ]]; then
	exit 1
fi

echo "API example contract check passed."
