require "rubygems"
require "uri"
require "digest/sha1"
require "base64"
require "rack/utils"
require "curl"
require "crack"

module Cloudquery
  SCHEME = "https".freeze
  HOST = "api.xoopit.com".freeze
  PATH = "/v0".freeze

  API_PATHS = {
    :account => "account",
  }.freeze


  SIGNING_METHOD = "SHA1"
  COOKIE_JAR = ".cookies.lwp"

  class Request
    attr_accessor :method, :headers, :scheme, :host, :port, :path, :params, :body

    def initialize(options={})
      @method = options[:method] || 'POST'
      @headers = options[:headers] || []
      @scheme = options[:scheme] || SCHEME
      @host = options[:host] || HOST
      @port = options[:port] || URI::HTTPS::DEFAULT_PORT
      @path = options[:path] || PATH
      @params = options[:params] || {}
      @body = options[:body]
      
      @account = options[:account]
      @secret = options[:secret]
    end

    def request_uri(account=@account, secret=@secret)
      uri = "#{@path}?#{query_str(signature_params(account))}"
      uri = append_signature(uri, secret) if secret
      uri
    end

    def url(account=@account, secret=@secret)
      base_uri.merge(request_uri(account, secret)).to_s
    end

    private
    def append_signature(uri, secret)
      sig = Crypto::Sha1.sign(secret, uri)
      x_sig = Rack::Utils.build_query("x_sig" => sig.tr('+/', '-_'))
      "#{uri}&#{x_sig}"
    end

    def signature_params(account=@account)
      return {} unless account
      {
        'x_name' => account,
        'x_time' => Time.now.to_i_with_milliseconds,
        'x_nonce' => Cloudquery::Crypto::Random.number,
        'x_method' => SIGNING_METHOD,
      }
    end

    def query_str(additional_params={})
      Rack::Utils.build_query(@params.dup.merge(additional_params))
    end

    def base_uri
      uri_class = if @scheme == 'https'
        URI::HTTPS
      else
        URI::HTTP
      end
      uri_class.build(:scheme => @scheme, :host => @host, :port => @port)
    end

  end

  module Crypto
    module Random
      extend self

      SecureRandom = (defined?(::SecureRandom) && ::SecureRandom) || (defined?(::ActiveSupport::SecureRandom) && ::ActiveSupport::SecureRandom)
      if SecureRandom
        def number
          "#{SecureRandom.random_number}.#{Time.now.to_i}"[2..-1]
        end
      else
        def number
          "#{rand.to_s}.#{Time.now.to_i}"[2..-1]
        end
      end

    end

    module Sha1
      extend self

      def sign(*tokens)
        tokens = tokens.flatten
        digest = Digest::SHA1.digest(tokens.join)
        Base64.encode64(digest).chomp
      end

    end
  end

  class Client
    attr_reader :account
    attr_writer :secret

    def initialize(options={})
      unless options[:account] && options[:secret]
        raise "Client requires :account => <account name> and :secret => <secret>"
      end
      @account = options[:account]
      @secret = options[:secret]
      @secure = options[:secure] != false # must pass false for insecure
    end

    def get_account
      send_request build_request(:method => 'GET', :path => build_path(API_PATHS[:account], @account))
    end

    private
    def build_path(*path_elements)
      path_elements.flatten.unshift(PATH).join('/')
    end
    
    def build_request(options={})
      Request.new default_request_params.merge(options)
    end
    
    def default_request_params
      {
        :account => @account,
        :secret => @secret,
        :scheme => @secure ? 'https' : 'http',
      }
    end
    
    def send_request(request)
      response = execute_request(request.method, request.url, request.headers, request.body)
      Crack::JSON.parse(response.last)
    end

    def execute_request(method, url, headers, body)
      curl = Curl::Easy.new(url) do |c|
        c.verbose = true
        c.headers = headers
      end
      
      case method
      when 'GET'
        curl.http_get
      when 'POST'
        curl.http_post(body)
      end
      
      [curl.response_code, curl.header_str, curl.body_str]
    end
  end
end


class Time
  def to_i_with_milliseconds
    (to_f * 1000).to_i
  end
end
