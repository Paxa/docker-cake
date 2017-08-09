require 'optparse'
require 'socket'
require_relative '../docker_cake'

options = {}
parser = OptionParser.new do |opts|
  opts.banner = "Usage: docker-cake [options] REPO"

  opts.on("-v", "--[no-]verbose", "Run verbosely") do |v|
    options[:verbose] = v
  end

  opts.on("-u", "--user [USER]", "Username, required for private repos") do |v|
    options[:user] = v
  end

  opts.on("-p", "--password [PASSWORD]", "Password, required for private repos") do |v|
    options[:password] = v
  end

  opts.on("-r", "--registry [REGISTRY URL]", "Docker registry URL, default is https://registry.hub.docker.com") do |v|
    options[:url] = v
  end

  opts.on("-l", "--layers", "Print layers of image") do |v|
    options[:layers] = v
  end

  opts.on("-n", "--max [NUM TAGS]", "Number of tags to analyse, default is 10") do |v|
    options[:max] = v
  end

end

parser.parse!

if options[:verbose]
  ENV['DEBUG'] = '1'
  p options
end

repo = ARGV.first
tag = ARGV[1]

if !repo || repo == ''
  puts "Repository name is required"
  puts "Example:"
  puts "    docker-cake library/ruby"
  puts "    docker-cake --help"
  exit(1)
end

connect_options = {
  user: options[:user],
  password: options[:password],
  url: options[:url]
}

begin
  if options[:layers]
    DockerCake.new(connect_options).repo_info(repo, tag || 'latest')
  else
    opts = {}
    opts[:max] = options[:max].to_i if options[:max]
    DockerCake.new(connect_options).compare_versions(repo, opts)
  end
rescue RegistryApiClient::RegistryAuthenticationException => e
  puts "Permission denied, make sure username and password are correct"
  puts "Server response: #{e.message}"
  puts "Example:"
  puts "    docker-cake bob/private_repo -u bob -p ***"
  exit 1
rescue RegistryApiClient::HTTP::NotFound => e
  if options[:layers]
    puts "Repository or tag not found"
  else
    puts "Repository not found"
  end
  puts "Example:"
  puts "    docker-cake library/ruby"
  exit 1
rescue RegistryApiClient::JsonError => error
  message = error.message.size > 300 ? error.message[0..300] + "..." : error.message
  puts "Error parsing JSON response: #{message} (#{(error.parent || error).class})"
  body = error.response.size > 300 ? error.response[0..300] + "..." : error.response
  puts "Server response body: #{body}"
  if ENV['DEBUG']
    headers = error.response.headers.to_a.map {|pair| pair.join(": ")}.join("\n  ")
    puts "Headers:\n  #{headers}"
  end
  exit 1
rescue SocketError => e
  puts "Can not connect to registery:"
  puts "#{e.class}: #{e.message}"
  puts e.backtrace if ENV['DEBUG']
  exit 1
end