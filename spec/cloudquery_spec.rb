require 'spec_helper'

describe Cloudquery::Request do
  before(:each) do
    @valid_options = {
      :scheme => 'http',
      :host => 'example.com',
      :path => '/v0/',
    }
  end
  
  def request(additional_options={})
    return @request if defined?(@request)
    @request = Cloudquery::Request.new(@valid_options.merge(additional_options))
  end

  it "instantiates with valid options" do
    lambda { request }.should_not raise_error
  end

  describe "add_authentication_params" do
    before(:each) do
      request.add_authentication_params('account')
    end
    
    it "should add the x_name parameter with the account name" do
      request.params.should have_key('x_name')
      request.params['x_name'].should == 'account'
    end
    
    it "should add the x_time parameter with the current milliseconds since epoch" do
      request.params.should have_key('x_time')
      request.params['x_time'].should be_close(Time.now.to_i_with_milliseconds, 100)
    end
    
    it "should add the x_nonce parameter of the format \d+.\d+" do
      request.params.should have_key('x_nonce')
      request.params['x_nonce'].should match(/^\d+.\d+$/)
    end
    
    it "should add the x_method parameter with the signing method name" do
      request.params.should have_key('x_method')
      request.params['x_method'].should == Cloudquery::SIGNING_METHOD
    end
  end

  describe "append_signature" do
    it "should append the signature as the x_sig parameter at the end of the query string"
  end
end

describe Cloudquery::Crypto::Random do
  describe "nonce generation" do
    it "generates a nonce with a random number, a dot, and the current time" do
      nonce = Cloudquery::Crypto::Random.number
      nonce.should match(/^\d+.\d+$/)
      random_digits, time = nonce.split('.')
      time.to_i.should be_close(Time.now.to_i, 1)
      random_digits.should match(/^\d+$/)
    end
  end
end
  