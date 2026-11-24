# frozen_string_literal: true

require_relative "dstu_core/version"
# A precompiled platform gem (rb-sys-dock) ships one extension per Ruby minor, under
# lib/dstu_core/<major.minor>/; a source build puts it directly in lib/dstu_core/ (D-268). Chosen by
# directory, not by rescuing LoadError, so a real load failure is reported as itself.
ruby_minor = RUBY_VERSION[/\A\d+\.\d+/]
if File.directory?(File.join(__dir__, "dstu_core", ruby_minor))
  require "dstu_core/#{ruby_minor}/dstu_core_rb"
else
  require "dstu_core/dstu_core_rb"
end
require_relative "dstu_core/secretstream"
