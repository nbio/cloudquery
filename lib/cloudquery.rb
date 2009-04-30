require "rubygems"
require "uri"
require "digest/sha1"
require "base64"

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
      @headers = options[:headers] || {}
      @scheme = options[:scheme] || SCHEME
      @host = options[:host] || HOST
      @port = options[:port] || URI::HTTPS::DEFAULT_PORT
      @path = options[:path] || PATH
      @params = options[:params] || {}
      @body = options[:body]
    end
    
    def add_authentication_params(account)
      @params['x_name'] = account
      @params['x_time'] = Time.now.to_i_with_milliseconds
      @params['x_nonce'] = Cloudquery::Crypto::Random.number
      @params['x_method'] = SIGNING_METHOD
    end
        
    def request_uri
      URI.build(:path => @path, :query => query_str).to_s
    end
    
    def signed_request_uri(secret)
      sign(request_uri, secret)
    end
    
    def uri
      base_uri.merge(request_uri).to_s
    end
    
    def signed_uri(secret)
      base_uri.merge(signed_request_uri).to_s
    end
    
  private
    def append_signature(uri, secret)
      signature = Crypto::Sha1.sign(secret, uri)
      url_safe_signature = URI.escape(signature.tr('+/', '-_'), /=/)
      "#{uri}&x_sig=#{url_safe_signature}"
    end
    
    def query_str
       @params.to_params
    end
    
    def base_uri
      URI.build(:scheme => @scheme, :host => @host, :port => @port)
    end
    
    def hash_to_params(hash)
      hash.map { |k, v| URI.escape("#{k}=#{v}") }.join('&')
      URI.escape(query_str, /@/)
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
      @account = options[:account]
      @secret = options[:secret]
      @secure = options[:secure] != false # must pass false for insecure
    end
    
    def get_account
      send_request Request.new(:path => build_path(API_PATHS[:account], account))
    end
    
    private
    def send_request(request)
      p request
    end
    
    def build_path(*path_elements)
      path_elements.flatten.unshift(PATH).join('/')
    end
  end
end

class Time
  def to_i_with_milliseconds
    (to_f * 1000).to_i
  end
end
