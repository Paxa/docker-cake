Gem::Specification.new do |gem|
  gem.specification_version = 3

  gem.name = 'docker-cake'
  gem.version = "0.1"
  gem.authors = ["Pavel Evstigneev"]
  gem.email = ["pavel.evst@gmail.com"]
  gem.license = 'MIT'
  gem.date = '2017-08-08'
  gem.summary = "Command line program to inspect docker images size"
  gem.homepage = 'https://github.com/paxa/docker-cake'

  gem.files = `git ls-files`.split("\n")
  gem.require_path = 'lib'
  gem.executables   = ["docker-cake"]

  gem.required_ruby_version = '>= 2.0'

  gem.add_dependency 'terminal-table', ['>= 1.8.0', '<3']
end
