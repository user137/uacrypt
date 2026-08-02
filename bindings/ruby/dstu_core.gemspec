# frozen_string_literal: true

require_relative "lib/dstu_core/version"

Gem::Specification.new do |spec|
  spec.name = "dstu_core"
  spec.version = DstuCore::VERSION
  spec.authors = ["dstu-core contributors"]
  spec.summary = "Ruby bindings for dstu-core (Ukrainian DSTU cryptographic standards)"
  spec.description = "magnus/rb_sys bindings exposing dstu-core's full crypto_* surface " \
                      "(secretbox, secretstream, sign, auth, kdf, generichash, stream, pwhash, " \
                      "randombytes) plus a self_test check - provisional, not yet published to " \
                      "RubyGems."
  spec.homepage = "https://github.com/user137/uacrypt"
  spec.licenses = ["MIT", "Apache-2.0"]
  spec.required_ruby_version = ">= 3.1"

  # Recursive glob (D-128's Node `files` gotcha, Ruby form): a single-level glob here would ship
  # Cargo.toml/build.rs/extconf.rb but silently omit src/*.rs, plus the gem-root Cargo.toml
  # (the workspace anchor, D-133) and Cargo.lock - a gem that can't actually compile on install.
  spec.files = Dir.glob("lib/**/*.rb") +
               Dir.glob("ext/**/*.{rs,toml,rb}") +
               ["Cargo.toml", "Cargo.lock", "Rakefile"]
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/dstu_core_rb/extconf.rb"]

  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "rb_sys", "~> 0.9"
  spec.add_development_dependency "rspec", "~> 3.13"
end
