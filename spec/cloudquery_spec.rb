require 'spec_helper'

describe Cloudquery do
  before(:each) do
    @valid_arguments = ['account', {}]
  end
  
  def client
    return @client if defined?(@client)
    @client = Cloudquery.new(*@valid_arguments)
    @client.stub!(:send_request)
    @client
  end
  
  it "instantiates when passed valid arguments" do
    lambda { client }.should_not raise_error
  end
  
  describe "API endpoint" do
    it "uses the secure endpoint by default" do
      client.endpoint_url.should == Cloudquery::SECURE_ENDPOINT
    end

    it "parses the scheme from the endpoint" do
      client.scheme.should == URI.parse(Cloudquery::SECURE_ENDPOINT).scheme
    end

    it "parses the host from the endpoint" do
      client.host.should == URI.parse(Cloudquery::SECURE_ENDPOINT).host
    end

    it "parses the path from the endpoint" do
      client.path.should == URI.parse(Cloudquery::SECURE_ENDPOINT).path
    end
  end
  
  describe "URL munging" do
    it "merges paths together to create a full URL" do
      path = "path/elements/and/stuff"
      client.send(:construct_url, path).should == "#{client.endpoint_url}#{path}"
    end
    
    it "merges paths and the query string to create a full URL" do
      path = "a/path"
      query_string = "query=param&foo=bar"
      client.send(:construct_url, path, query_string).should == "#{client.endpoint_url}#{path}?#{query_string}"
    end
    
    it "extracts the normalized, signable url from the full URL" do
      request_uri = "/path/elements/?query=string"
      url = "https://subdomain.domain.tld:9027#{request_uri}"
      client.send(:normalize_url_for_signing, url).should == request_uri
    end
  end
  
  describe "nonce generation" do
    it "generates a nonce with a random number, a dot, and the current time" do
      nonce = Crypto::Random.number
      nonce.should match(/^\d+.\d+$/)
      random_digits, time = nonce.split('.')
      time.to_i.should be_close(Time.now.to_i, 1)
      random_digits.should match(/^\d+$/)
    end
  end
  
  describe "cryptographic signing" do
    before(:each) do
      @url = 'https://a.url.to-sign/with/a/path'
    end
    
    it "supports SHA1 as the signing method" do
      client.signing_method.should == 'SHA1'
      lambda {
        client.send(:append_signature, @url)
      }.should_not raise_error
    end
    
    it "raises an exception for unsupported signing methods" do
      client.should_receive(:signing_method).at_least(:once).and_return("BCrypt")
      lambda {
        client.send(:append_signature, @url)
      }.should raise_error("The BCrypt signing method is not supported")
    end
    
    it "appends the signature as the x_sig parameter at the end of the full url" do
      signed_url = client.send(:append_signature, @url)
      signed_url.should match(/^#{@url}/)
      signed_url.should match(/x_sig=[-\w]+(?:%3D)*$/)
    end
    
    it "encodes the signature with url-safe base64" do
      signature = client.send(:append_signature, @url).split('x_sig=').last
      signature.should_not include('+')
      signature.should_not include('/')
    end
  end
  
  describe "request url signing" do
    it "keeps reserved characters out of the query" do
      params = {"escape_me" => "account@example.com", "foo" => "bar"}
      url = "https://subdomain.domain.tld:9027/path/elements/"
      client.sign_request_url(url, params).should_not match(/@/)
    end
  end
  
  describe "#authenticate" do
    it "raises an exception unless a password is provided" do
      lambda { client.authenticate }.should raise_error(ArgumentError)
      
    end
    
    it "raises an exception unless the client is secure" do
      client.should_receive(:secure?).and_return(false)
      lambda {
        client.authenticate('password')
      }.should raise_error("Authentication using this method is only allowed over HTTPS")
      
    end
    
    it "sends a request with a descriptor to post params to the authentication url" do
      params = {'name' => @valid_arguments.first, 'password' => 'password'}
      client.should_receive(:send_request) do |request_descriptor|
        request_descriptor.shift.should == 'POST'
        request_descriptor.shift.should == client.send(:construct_url, Cloudquery::API_PATHS[:authenticate])
        request_descriptor.shift.should == params.to_query_string
      end
      client.authenticate('password')
    end
  end
end
