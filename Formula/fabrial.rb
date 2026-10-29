# typed: false
# frozen_string_literal: true

# Formula for Fabrial (bonjoski/fabrial)
# The Sovereign AI Agent Security Fabric: Airlock, Locksmith, Aegisbox, and Argus.
class Fabrial < Formula
  desc "Sovereign AI agent security fabric unifying Airlock, Locksmith, Aegisbox, Argus"
  homepage "https://github.com/bonjoski/fabrial"
  url "https://github.com/bonjoski/fabrial/archive/refs/tags/v0.4.1.tar.gz"
  sha256 "9a5ca19b72d33cf2209e1d042a4ddc9c15db8a264d3556c89cabd1f4b41f8632"
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
