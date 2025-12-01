class Qault < Formula
  desc "CLI password manager hardened for post-quantum crypto"
  homepage "https://github.com/klevo/qault"
  url "https://github.com/klevo/qault.git", branch: "main"
  version "0.0.0"
  license "MIT"
  head "https://github.com/klevo/qault.git", branch: "main"

  depends_on "go" => :build

  def install
    ldflags = %W[
      -s -w
      -X qault/internal/cli.Version=#{version}
    ]
    system "go", "build", *std_go_args(ldflags: ldflags.join(" ")), "./cmd/qault"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/qault version").strip
  end
end
