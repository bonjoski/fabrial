# typed: false
# frozen_string_literal: true

# Formula for Fabrial (bonjoski/fabrial)
# The Sovereign AI Agent Security Fabric: Airlock, Locksmith, Aegisbox, and Argus.
class Fabrial < Formula
  desc "Sovereign AI Agent Security Fabric: Unifying Airlock, Locksmith, Aegisbox, and Argus"
  homepage "https://github.com/bonjoski/airlock"
  url "https://github.com/bonjoski/airlock/archive/refs/tags/v0.6.0.tar.gz"
  sha256 "PLACEHOLDER_SOURCE_SHA256"
  license "MIT"
  head "https://github.com/bonjoski/airlock.git", branch: "main"

  depends_on "go" => :build

  on_linux do
    depends_on "bubblewrap"
  end

  def install
    ldflags = %W[
      -s -w
      -X github.com/bonjoski/airlock/pkg/version.Version=#{version}
      -X github.com/bonjoski/airlock/pkg/version.Commit=brew
      -X github.com/bonjoski/airlock/pkg/version.BuildTime=#{time.iso8601}
    ]

    system "go", "build", *std_go_args(ldflags: ldflags.join(" ")), "./cmd/airlock"
    system "go", "build", *std_go_args(output: bin/"fabrial", ldflags: ldflags.join(" ")), "./cmd/fabrial"
    system "go", "build", *std_go_args(output: bin/"airlock-mcp", ldflags: ldflags.join(" ")), "./cmd/airlock-mcp"
  end

  def caveats
    <<~EOS
      💎 Fabrial Security Fabric has been installed!

      To check the health of all four security pillars (Airlock, Locksmith, Aegisbox, Argus):
        fabrial doctor

      Run sandboxed agent commands:
        # Tier 1: Fast Kernel Confinement (<15ms)
        fabrial exec --profile agent -- <command>

        # Tier 2: MicroVM Confinement (~100ms via Aegisbox hypervisor)
        fabrial exec --profile agent --microvm -- <command>
    EOS
  end

  test do
    assert_match "Fabrial Unified Fabric", shell_output("#{bin}/fabrial version")
    assert_match "Fabrial Multi-Pillar Diagnostic Suite", shell_output("#{bin}/fabrial doctor")
  end
end
