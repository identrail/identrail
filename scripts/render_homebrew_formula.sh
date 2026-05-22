#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <tag> <source-sha256>" >&2
  exit 2
fi

tag="$1"
source_sha256="$2"

if ! [[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release tag: ${tag}" >&2
  exit 2
fi

if ! [[ "${source_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "invalid source sha256: ${source_sha256}" >&2
  exit 2
fi

cat <<FORMULA
class Identrail < Formula
  desc "Open-source machine identity security for AWS and Kubernetes"
  homepage "https://www.identrail.com"
  url "https://github.com/identrail/identrail/archive/refs/tags/${tag}.tar.gz"
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
