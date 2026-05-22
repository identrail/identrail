#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <tag> <source-url> <source-sha256>" >&2
  exit 2
fi

tag="$1"
source_url="$2"
source_sha256="$3"

if ! [[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release tag: ${tag}" >&2
  exit 2
fi

if ! [[ "${source_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "invalid source sha256: ${source_sha256}" >&2
  exit 2
fi

expected_url_prefix="https://github.com/identrail/identrail/releases/download/${tag}/"
if [[ "${source_url}" != "${expected_url_prefix}"* ]]; then
  echo "invalid source url for ${tag}: ${source_url}" >&2
  exit 2
fi

cat <<FORMULA
class Identrail < Formula
  desc "Open-source machine identity security for AWS and Kubernetes"
  homepage "https://www.identrail.com"
  url "${source_url}"
  sha256 "${source_sha256}"
  license "Apache-2.0"
  head "https://github.com/identrail/identrail.git", branch: "dev"

  depends_on "go" => :build

  def install
    system "go", "build", "-trimpath", "-ldflags", "-s -w", "-o", bin/"identrail", "./cmd/cli"
  end

  test do
    assert_match "Machine identity security scanner", shell_output("#{bin}/identrail --help")
    assert_match "scan [repository]", shell_output("#{bin}/identrail scan --help")
  end
end
FORMULA
