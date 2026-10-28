# typed: false
# frozen_string_literal: true

# Formula for Fabrial (bonjoski/fabrial)
# The Sovereign AI Agent Security Fabric: Airlock, Locksmith, Aegisbox, and Argus.
class Fabrial < Formula
  desc "Sovereign AI agent security fabric unifying Airlock, Locksmith, Aegisbox, Argus"
  homepage "https://github.com/bonjoski/fabrial"
  url "https://github.com/bonjoski/fabrial/archive/refs/tags/v0.4.0.tar.gz"
  sha256 "de0ced552bf831ac1b69871cc346f8b06e72e7fd7847f7bdcad24187e0ea8e47"
  license "Apache-2.0"
  head "https://github.com/bonjoski/fabrial.git", branch: "main"

  depends_on "go" => :build

  # Four Security Fabric Pillars
  depends_on "bonjoski/locksmith/locksmith"
  depends_on "bonjoski/tap/aegisbox"
  depends_on "bonjoski/tap/airlock"
  depends_on "bonjoski/tap/argus"

  on_linux do
    depends_on "bubblewrap"
  end

  def install
    ldflags = %W[
      -s -w
      -X github.com/bonjoski/fabrial/pkg/version.Version=#{version}
      -X github.com/bonjoski/fabrial/pkg/version.Commit=brew
      -X github.com/bonjoski/fabrial/pkg/version.BuildTime=#{time.iso8601}
    ]

    system "go", "build", *std_go_args(output: bin/"fabrial", ldflags: ldflags.join(" ")), "./cmd/fabrial"
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
