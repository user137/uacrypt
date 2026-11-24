# frozen_string_literal: true

require "fileutils"
require "open3"
require "rbconfig"
require "tmpdir"

# lib/dstu_core.rb's extension loader (D-268): a precompiled platform gem keeps one extension per
# Ruby minor under lib/dstu_core/<minor>/, a source build keeps it flat. Every published platform gem
# up to 0.5.1 failed to load because only the flat layout was tried. Each case runs a fresh `ruby`
# against a stub extension, since the real one is already loaded in this process.
RSpec.describe "DstuCore extension loader" do
  minor = RUBY_VERSION[/\A\d+\.\d+/]
  loader = File.expand_path("../lib/dstu_core.rb", __dir__)

  def load_with(loader, ext_dir, ext_body)
    Dir.mktmpdir do |root|
      lib = File.join(root, "lib")
      FileUtils.mkdir_p(File.join(lib, ext_dir))
      FileUtils.cp(loader, File.join(lib, "dstu_core.rb"))
      File.write(File.join(lib, "dstu_core", "version.rb"), "module DstuCore; VERSION = 'x'; end\n")
      File.write(File.join(lib, "dstu_core", "secretstream.rb"), "")
      File.write(File.join(lib, ext_dir, "dstu_core_rb.rb"), ext_body)
      script = 'begin; require "dstu_core"; print $loaded; rescue LoadError => e; print "LoadError: " + e.message; end'
      out, status = Open3.capture2(RbConfig.ruby, "-I", lib, "-e", script)
      raise "stub ruby exited #{status}" unless status.success?

      out
    end
  end

  it "loads a source build's flat extension" do
    expect(load_with(loader, "dstu_core", "$loaded = :flat\n")).to eq("flat")
  end

  it "loads a platform gem's per-minor extension" do
    expect(load_with(loader, "dstu_core/#{minor}", "$loaded = :versioned\n")).to eq("versioned")
  end

  it "reports a real load failure of the per-minor extension instead of masking it" do
    out = load_with(loader, "dstu_core/#{minor}", "raise LoadError, 'real load failure'\n")
    expect(out).to eq("LoadError: real load failure")
  end
end
