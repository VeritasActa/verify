class VeritasactaVerify < Formula
  desc "Offline verifier for Veritas Acta signed decision receipts"
  homepage "https://veritasacta.com"
  url "https://registry.npmjs.org/@veritasacta/verify/-/verify-0.5.0.tgz"
  sha256 "8c20600b727bb3fe725734d2614fe13b5bccb71ededae7596c7554b2514bfc6b"
  license "Apache-2.0"
  head "https://github.com/VeritasActa/verify.git", branch: "main"

  depends_on "node"

  def install
    system "npm", "install", *Language::Node.std_npm_args(libexec)
    bin.install_symlink Dir["#{libexec}/bin/*"]
  end

  def caveats
    <<~EOS
      After install, compare monitored verifier source with the bundled commitment:
        veritasacta-verify --self-check

      For publisher authentication, independently obtain and pin the expected
      Sigil fingerprint before relying on this comparison.

      Start signing receipts with:
        veritasacta-verify init

      Protocol:  https://veritasacta.com
      Managed:   https://scopeblind.com (optional)
    EOS
  end

  test do
    # Self-check compares monitored verifier source with the bundled commitment.
    assert_match "Monitored verifier source matches bundled commitment", shell_output("#{bin}/veritasacta-verify --self-check")
  end
end
