Gem::Specification.new do |spec|
  spec.name              = 'aesruby'
  spec.version           = '0.1.0'
  spec.summary           = 'Ruby bindings for C implementation of AES.'
  spec.files             = Dir.glob('ext/*.{c,h}') + %w(ext/extconf.rb README.txt)
  spec.author            = 'abc'
  spec.email             = 'abc@example.com'
  spec.homepage          = 'http://svn.coderepos.org/share/lang/ruby/aesruby/'
  spec.extensions        = 'ext/extconf.rb'
  spec.has_rdoc          = true
  spec.extensions        = 'ext/extconf.rb'
  spec.has_rdoc          = true
  spec.rdoc_options      << '--title' << 'AES/Ruby - Ruby bindings for C implementation of AES.'
  spec.extra_rdoc_files  = %w(README.txt ext/aesruby.c)
  spec.rubyforge_project = 'aesruby'
end
