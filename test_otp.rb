# frozen_string_literal: true

require 'minitest/autorun'
require './otp'

class OTPTest < Minitest::Test
  def setup
    @otp = OTP.new('ABCDEFGHIJKLMNOPQRSTUVWXYZ ')
  end

  def test_encrypt
    p = 'TEST'
    k = 'ASDF'

    assert_equal 'TWVY', @otp.encrypt(p, k)
  end

  def test_decrypt
    c = 'TWVY'
    k = 'ASDF'

    assert_equal 'TEST', @otp.decrypt(c, k)
  end

  def test_encrypt_pads_to_key_size
    p = 'TEST'
    k = 'ASDFASDF'
    c = @otp.encrypt(p, k)

    assert_equal c.length, k.length
  end

  def test_encrypt_limits_alphabet
    e = assert_raises(RuntimeError) { @otp.encrypt('test', 'ASDF') }
    assert_equal "Message contains invalid symbol 't'", e.message

    e = assert_raises(RuntimeError) { @otp.encrypt('TEST', 'asdf') }
    assert_equal "Key contains invalid symbol 'a'", e.message
  end

  def test_decrypt_limits_alphabet
    e = assert_raises(RuntimeError) { @otp.decrypt('test', 'ASDF') }
    assert_equal "Message contains invalid symbol 't'", e.message

    e = assert_raises(RuntimeError) { @otp.decrypt('TEST', 'asdf') }
    assert_equal "Key contains invalid symbol 'a'", e.message
  end

  def test_encrypt_message_not_longer_than_key
    e = assert_raises(RuntimeError) { @otp.encrypt('AB', 'A') }
    assert_equal 'Message too long for key of size 1', e.message
  end
end
