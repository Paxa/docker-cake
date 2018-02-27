require 'json'
require 'uri'
require 'socket'
require 'net/http'

class RegistryApiClient

  class RegistryAuthenticationException < Exception
  end

  class RegistryAuthorizationException < Exception
  end

  class RegistryUnknownException < Exception
  end

  class RegistrySSLException < Exception
  end
  
  class ReauthenticatedException < Exception
  end
  
  class UnknownRegistryException < Exception
  end

  class InvalidMethod < Exception
  end

  class JsonError < Exception
    attr_reader :response
    attr_reader :parent
    def initialize(message, response = nil)
      super(message)
      @parent = message if message.is_a?(Exception)
      @response = response
    end
  end

  class Waiter
    def initialize
      @queue = Queue.new
    end

    # Waiting for someone to call #notify
    def wait
      @queue.pop(false)
    end

    # Notify waiting side
    def notify(data)
      @queue.push(data)
    end
  end

  # It's same as waiter but support multiple subscribers
  class PubSub
    def initialize
      @waiters = []
    end

    def wait
      waiter = Waiter.new
      @waiters << waiter
      waiter.wait
    end

    def notify(value)
      while waiter = @waiters.shift
        waiter.notify(value)
      end
    end
  end

  DEFAULT_REGISTRY = "https://registry.hub.docker.com"
  DEFAULT_MANIFEST = "application/vnd.docker.distribution.manifest.v1+json"
  FAT_MANIFEST =     "application/vnd.docker.distribution.manifest.list.v2+json"

  # @param [#to_s] base_uri Docker registry base URI
  # @param [Hash] options Client options
  # @option options [#to_s] :user User name for basic authentication
  # @option options [#to_s] :password Password for basic authentication
  def initialize(url: DEFAULT_REGISTRY, user: nil, password: nil)
    url = url || DEFAULT_REGISTRY
    @url = url
    uri = URI.parse(url)
    @base_uri = "#{uri.scheme}://#{uri.host}:#{uri.port}"
    @user = user
    @password = password
    @manifest_format = "application/vnd.docker.distribution.manifest.v2+json"
    #@manifest_format = "application/vnd.docker.distribution.manifest.list.v2+json"
    #@manifest_format = "application/vnd.docker.container.image.v1+json"
    # make a ping connection
    #ping
  end

  def http_get(url, manifest: nil, auth: nil, auth_header: nil)
    http_req("get", url, manifest: manifest, auth: auth, auth_header: auth_header)
  end

  def http_delete(url)
    http_req("delete", url)
  end

  def http_head(url)
    http_req("head", url)
  end

  def ping
    response = http_get('/v2/')
  end

  def search(query = '')
    response = http_get "/v2/_catalog"
    # parse the response
    repos = JSON.parse(response)["repositories"]
    if query.strip.length > 0
      re = Regexp.new query
      repos = repos.find_all {|e| re =~ e }
    end
    return repos
  end

  def tags(repo, withHashes = false)
    response = http_get("/v2/#{repo}/tags/list")
    # parse the response
    resp = begin
      JSON.parse(response)
    rescue JSON::ParserError => e
      raise JsonError.new(e, response)
    end
    # do we include the hashes?
    if withHashes then
      useGet = false
      resp["hashes"] = {}
      resp["tags"].each {|tag|
        if useGet then
          head = http_get "/v2/#{repo}/manifests/#{tag}"
        else
          begin
            head = http_head("/v2/#{repo}/manifests/#{tag}")
          rescue InvalidMethod
            # in case we are in a registry pre-2.3.0, which did not support manifest HEAD
            useGet = true
            head = http_get("/v2/#{repo}/manifests/#{tag}")
          end
        end
        resp["hashes"][tag] = head.headers[:docker_content_digest]
      }
    end

    return resp
  end

  # combines small output and fat output to get layer names and sizes
  def manifest(repo, tag, manifest: nil)
    if @url == DEFAULT_REGISTRY
      auth_header = %{Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:#{repo}:pull"}
    end
    JSON.parse(http_get("/v2/#{repo}/manifests/#{tag}", manifest: manifest, auth: :bearer, auth_header: auth_header))
  end

  def manifest_layers(repo, tag)
    basic_response = nil
    fat_response = nil

    resp = in_parallel(
      basic: lambda { manifest(repo, tag) },
      fat:   lambda { manifest(repo, tag, manifest: DEFAULT_MANIFEST) }
    )

    unless resp[:basic]['layers']
      puts "Strange response"
      p resp[:basic]
    end

    basic = resp[:basic]['layers'] || []
    fat_response = resp[:fat]

    result = []

    fat_response['history'].each_with_index do |info, index|
      result[index] = JSON.parse(info['v1Compatibility'])
      result[index]['blobSum'] = fat_response['fsLayers'][index]['blobSum']
      result[index]['size'] = basic.detect do |layer|
        layer['digest'] == result[index]['blobSum']
      end
      result[index]['size'] = result[index]['size']['size'] if result[index]['size']
    end

    # require 'irb'
    # binding.irb

    result.reverse
  end

  def in_parallel(procs = {})
    threads = []
    result = {}
    errors = []
    procs.each do |key, fun|
      # handle array
      if fun == nil && key.is_a?(Proc)
        fun = key
        key = result.size
      end
      result[key] = nil
      threads << Thread.new do
        begin
          result[key] = fun.call
        rescue => error
          puts "#{error.class}: #{error.message}"
          puts error.backtrace
          errors << error
        end
      end
    end

    threads.each do |t|
      t.alive? && t.join
    end

    if errors.size > 0
      raise errors.first
    end

    result
  end

  # gets the size of a particular blob, given the repo and the content-addressable hash
  # usually unneeded, since manifest includes it
  def blob_size(repo, blobSum)
    response = http_head("/v2/#{repo}/blobs/#{blobSum}")
    Integer(response.headers[:content_length], 10)
  end

  def manifest_sum(manifest)
    size = 0
    manifest["layers"].each do |layer|
      size += layer["size"]
    end
    size
  end

  private
    def http_req(type, url, stream: nil, manifest: nil, auth: nil, auth_header: nil)
      begin
        if auth == :bearer && auth_header
          return do_bearer_req(type, url, auth_header, stream: stream, manifest: manifest)
        else
          return req_no_auth(type, url, stream: stream, manifest: manifest)
        end
#      rescue SocketError => e
#        p e
#        raise RegistryUnknownException
      rescue HTTP::Unauthorized => e
        header = e.response.headers[:www_authenticate]
        method = header.downcase.split(' ')[0]
        case method
        when 'basic'
          response = do_basic_req(type, url, stream: stream, manifest: manifest)
        when 'bearer'
          response = do_bearer_req(type, url, header, stream: stream, manifest: manifest)
        else
          raise RegistryUnknownException
        end
      end
      return response
    end

    def req_no_auth(type, url, stream: nil, manifest: nil)
      block = stream.nil? ? nil : proc do |response|
        response.read_body do |chunk|
          stream.write chunk
        end
      end
      response = HTTP.execute(
        method: type,
        url: @base_uri + url,
        headers: {Accept: manifest || @manifest_format},
        block_response: block
      )
    end

    def do_basic_req(type, url, stream: nil, manifest: nil)
      begin
        block = stream.nil? ? nil : proc { |response|
          response.read_body do |chunk|
            stream.write chunk
          end
        }
        response = HTTP.execute(
          method: type,
          url: @base_uri + url,
          user: @user,
          password: @password,
          headers: {Accept: manifest || @manifest_format},
          block_response: block
        )
#      rescue SocketError
#        raise RegistryUnknownException
      rescue HTTP::Unauthorized => error
        raise RegistryAuthenticationException.new(error)
      rescue HTTP::MethodNotAllowed
        raise InvalidMethod
      end
      return response
    end

    def do_bearer_req(type, url, header, stream: false, manifest: nil)
      token = authenticate_bearer(header)
      begin
        block = stream.nil? ? nil : proc { |response|
          response.read_body do |chunk|
            stream.write chunk
          end
        }
        response = HTTP.execute(
          method: type,
          url: @base_uri + url,
          headers: {Authorization: 'Bearer ' + token, Accept: manifest || @manifest_format},
          block_response: block
        )
#      rescue SocketError
#        raise RegistryUnknownException
      rescue HTTP::Unauthorized => e
        raise RegistryAuthenticationException.new(e)
      rescue HTTP::MethodNotAllowed
        raise InvalidMethod
      end

      return response
    end

    AUTH_CACHE = {}

    def authenticate_bearer(header)
      # get the parts we need
      target = split_auth_header(header)
      scope = target[:params][:scope]

      if AUTH_CACHE[scope].is_a?(String)
        return AUTH_CACHE[scope]
      elsif AUTH_CACHE[scope].is_a?(PubSub)
        result = AUTH_CACHE[scope].wait
        if result.is_a?(Exception)
          raise result
        else
          return result
        end
      else
        AUTH_CACHE[scope] = PubSub.new
      end

      # did we have a username and password?
      if defined? @user and @user.to_s.strip.length != 0
        target[:params][:account] = @user
      end
      # authenticate against the realm
      uri = URI.parse(target[:realm])
      begin
        response = HTTP.execute(
          method: :get,
          url: uri.to_s,
          query: target[:params],
          user: @user,
          password: @password
        )
      rescue HTTP::Unauthorized => error
        # bad authentication
        AUTH_CACHE[scope].notify(error)
        raise RegistryAuthenticationException.new(error)
      end
      # now save the web token
      token = JSON.parse(response)["token"]
      AUTH_CACHE[scope].notify(token)
      AUTH_CACHE[scope] = token
      return token
    end

    def split_auth_header(header = '')
      h = Hash.new
      h = {params: {}}
      header.split(/[\s,]+/).each {|entry|
        p = entry.split('=')
        case p[0]
        when 'Bearer'
        when 'realm'
          h[:realm] = p[1].gsub(/(^\"|\"$)/,'')
        else
          h[:params][p[0]] = p[1].gsub(/(^\"|\"$)/,'')
        end
      }
      h
    end

  module HTTP
    extend self

    class ResponseError < Exception
      attr_accessor :response
      def initialize(message, response)
        super(message)
        @response = response
      end
    end

    class Unauthorized < ResponseError
    end

    class MethodNotAllowed < ResponseError
    end

    class NotFound < ResponseError
    end

    def execute(method:, url:, headers: {}, user: nil, password: nil, block_response: nil, body: nil, query: nil)
      if query
        uri = URI.parse(url)
        url += (uri.query ? "&" : "?") + URI.encode_www_form(query)
      end
      uri = URI.parse(url)
      response = nil

      Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
        http_klass = case method.to_sym
          when :get    then Net::HTTP::Get
          when :post   then Net::HTTP::Post
          when :put    then Net::HTTP::Put
          when :patch  then Net::HTTP::Patch
          when :head   then Net::HTTP::Head
          when :delete then Net::HTTP::Delete
          when :move   then Net::HTTP::Move
          when :copy   then Net::HTTP::Copy
          else Net::HTTP::Post
        end

        request = http_klass.new(uri)
        headers.each do |key, value|
          request[key.to_s] = value
        end

        if body
          request.body = body
        end

        if user != nil || password != nil
          request.basic_auth(user, password)
        end

        puts "HTTP req #{method} #{url} #{headers}" if ENV['DEBUG']

        http_resp = http.request(request)

        puts "-> HTTP status: #{http_resp.code} size: #{http_resp.body.size}" if ENV['DEBUG']

        response = Response.new(http_resp)

        if http_resp.code.to_s == "401"
          raise Unauthorized.new(http_resp.body, response)
        end

        if http_resp.code.to_s == "405"
          raise MethodNotAllowed.new(http_resp.body, response)
        end

        if http_resp.code.to_s == '404'
          raise NotFound.new(http_resp.body, response)
        end

        return response
      end
    end

    class Response < String
      attr_accessor :headers

      def initialize(http_response)
        @http_response = http_response
        @headers = {}
        @http_response.to_hash.each do |key, value|
          @headers[key.gsub('-', '_').to_sym] = value.last
        end
        super(http_response.body)
      end
    end
  end
end