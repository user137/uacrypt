# frozen_string_literal: true

require_relative "lib/dstu_core/version"

Gem::Specification.new do |spec|
  spec.name = "dstu_core"
  spec.version = DstuCore::VERSION
  spec.authors = ["dstu-core contributors"]
  spec.summary = "Ruby bindings for dstu-core (Ukrainian DSTU cryptographic standards) - provisional, not yet published to RubyGems"
  spec.description = spec.summary
  spec.homepage = "https://github.com/user137/uacrypt"
  spec.licenses = ["MIT", "Apache-2.0"]
  spec.required_ruby_version = ">= 3.1"

  spec.files = Dir.glob("lib/**/*.rb") + Dir.glob("ext/dstu_core_rb/*.{rs,toml,rb}") + ["Rakefile"]
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/dstu_core_rb/extconf.rb"]

  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "rb_sys", "~> 0.9"
  spec.add_development_dependency "rspec", "~> 3.13"
end
