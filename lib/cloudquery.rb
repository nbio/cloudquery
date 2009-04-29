require "rubygems"
require "uri"
require "digest/sha1"
require "base64"
require "curl"

class Cloudquery
  
  KEEP_ALIVE = true
  RAISE_EXCEPTIONS = false
  INSECURE_ENDPOINT = "http://api.xoopit.com/v0/"
  SECURE_ENDPOINT = "https://api.xoopit.com/v0/"
  SIGNING_METHOD = "SHA1"
  
  COOKIE_JAR = '.cookies.lwp'
  
  API_PATHS = {
    :authenticate => 'auth',
  }.freeze
  
  attr_writer :secret
  attr_reader :account_name, :stats
  attr_reader :endpoint_url, :scheme, :host, :port, :path
  attr_reader :signing_method
  
  def initialize(account_name, options={})
    @account_name = account_name
    @secret = options[:secret]

    prepare_endpoint_ivars(options)
    
    @signing_method = SIGNING_METHOD
    @stats = {
      :info => nil,
      :timing => nil,
    }
  end
  
  def secure?
    !!@secure
  end
  
  # Signs a request in preparation for transit to the @endpoint_url
  def sign_request_url(path, params={})
    params['x_name'] = @account_name
    params['x_method'] = @signing_method
    params['x_time'] = Time.now.to_i_with_milliseconds
    params['x_nonce'] = Crypto::Random.number
    
    query_str = params.to_query_string
    constructed_url = construct_url(path, query_str)
    append_signature(constructed_url)
  end
  
  # Authenticate the account using the password
  def authenticate(password)
    raise "Authentication using this method is only allowed over HTTPS" unless secure?
    
    params = {
      'name' => @account_name,
      'password' => password,
    }
    
    request = ['POST', construct_url(API_PATHS[:authenticate]), params.to_query_string]
    send_request(request)
  end

private
  def prepare_endpoint_ivars(options)
    @secure = !options[:use_http]
    @endpoint_url = @secure ? SECURE_ENDPOINT : INSECURE_ENDPOINT
    e = URI.parse(@endpoint_url)
    @scheme, @host, @path = e.select(:scheme, :host, :path)
  end

  def construct_url(api_path, query_str="")
    uri_class = secure? ? URI::HTTPS : URI::HTTP
    uri = uri_class.build({
      :scheme => @scheme,
      :host => @host,
      :path => @path,
    })
    uri.merge!(api_path)
    uri.query = query_str unless query_str.to_s.empty?
    uri.to_s
  end

  def append_signature(url)
    signer = case signing_method
    when "SHA1"; Crypto::Sha1
    else; raise "The #{signing_method} signing method is not supported"
    end

    signable_url = normalize_url_for_signing(url)
    signature = signer.sign(@secret, signable_url)
    url_safe_signature = URI.escape(signature.tr('+/', '-_'), /=/)
    "#{url}&x_sig=#{url_safe_signature}"
  end
  
  # Expects a rack-style request descriptor
  # e.g. [HTTP_VERB, url, body]
  def send_request(descriptor)
    verb, url, body = descriptor
    
    @curl ||= Curl::Easy.new do |c|
      c.enable_cookies = true
      c.cookiejar = COOKIE_JAR
      c.verbose = true
    end
    
    @curl.url = url
    
    case verb
    when 'GET'
      @curl.http_get
    when 'POST'
      puts body
      @curl.http_post(body)
    end
    
  end
  
  def normalize_url_for_signing(url)
    URI.parse(url).request_uri
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

class Time
  def to_i_with_milliseconds
    (to_f * 1000).to_i
  end
end

class Hash
  
  def to_query_string
    query_str = map { |k, v| URI.escape("#{k}=#{v}") }.join('&')
    URI.escape(query_str, /@/)
  end
end