# frozen_string_literal: true

require 'securerandom'

class OTP
  attr_reader :alphabet

  def initialize(alphabet)
    @alphabet = alphabet
    if po2?
      puts 'Alphabet is of size 2^n, will use [P ⊕ K] (XOR) instead of [(P + K) % s]'
      @encrypt_func = @decrypt_func = ->(p, k) { p ^ k }
    else
      @encrypt_func = ->(p, k) { (p + k) % @alphabet.length }
      @decrypt_func = ->(p, k) { (p - k) % @alphabet.length }
    end
  end

  def encrypt(message, key)
    diff = key.length - message.length
    raise "Message too long for key of size #{key.length}" if diff.negative?

    # Pad the message to the key length to avoid leaking information
    # about the message length.
    message += ' ' * diff

    one_time_pad(message, key, &@encrypt_func)
  end

  def decrypt(message, key)
    one_time_pad(message, key, &@decrypt_func)
  end

  def pretty_print(label, str)
    char_format = ['%-15s', *('%3c' * str.length)].join(' ')
    int_format = ['%15c', *('%3d' * str.length)].join(' ')

    values = str.chars.map { |c| @alphabet.index(c) }

    puts format(char_format, label, *str.chars)
    puts format(int_format, ' ', *values), ''
  end

  def random_key(len)
    SecureRandom.send(:choose, @alphabet.chars, len)
  end

  private

  def one_time_pad(message, key)
    message.chars.map.with_index(0) do |char, idx|
      p = @alphabet.index(char)
      raise "Message contains invalid symbol '#{char}'" if p.nil?

      k = @alphabet.index(key[idx])
      raise "Key contains invalid symbol '#{key[idx]}'" if k.nil?

      encrypted_char = yield p, k

      @alphabet[encrypted_char]
    end.join
  end

  def po2?
    @po2 ||= Math.log2(@alphabet.length).denominator == 1
  end
end

if __FILE__ == $PROGRAM_NAME
  require 'optparse'

  options = {
    alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ '
  }

  opts = OptionParser.new
  opts.banner = 'Usage: otp.rb [--key <key>] [--alphabet <alphabet>] <message>'
  opts.on('-k', '--key KEY', 'Encryption Key') { |v| options[:key] = v }

  opts.on('-a', '--alphabet ALPHABET', 'Alphabet') do |alpha|
    if alpha.chars.group_by(&:itself).each_value.all? { |v| v.size == 1 }
      options[:alphabet] = alpha
    else
      puts 'Ignoring provided alphabet as it includes duplicate symbols'
    end
  end

  opts.parse!

  message = if ARGV.empty?
              'THERE IS NO SPOON'
            else
              ARGV.join(' ')
            end

  otp = OTP.new(options[:alphabet])

  key = options[:key] || otp.random_key(48)

  err = false

  bad_chars_in_key = key.chars.uniq - options[:alphabet].chars
  unless bad_chars_in_key.empty?
    puts "Key contains symbols not included in the alphabet. Bad symbols: #{bad_chars_in_key.join}"
    err = true
  end

  bad_chars_in_message = message.chars.uniq - options[:alphabet].chars
  unless bad_chars_in_message.empty?
    puts "Message contains symbols not included in the alphabet. Bad symbols: #{bad_chars_in_message.join}"
    err = true
  end

  if err
    puts 'Cannot continue, exiting'
    exit 1
  end

  otp.pretty_print('Alphabet', otp.alphabet)
  otp.pretty_print('Message', message)
  otp.pretty_print('Key', key)

  ciphertext = otp.encrypt(message, key)
  otp.pretty_print('Ciphertext', ciphertext)

  decrypted = otp.decrypt(ciphertext, key)
  otp.pretty_print('Decrypted', decrypted)

  puts format('%<label>-13s: "%<val>s"', label: 'Message', val: message)
  puts format('%<label>-13s: "%<val>s"', label: 'Key', val: key)
  puts format('%<label>-13s: "%<val>s"', label: 'Ciphertext', val: ciphertext)
  puts format('%<label>-13s: "%<val>s"', label: 'Decrypted', val: decrypted)
end

# Example output
# --------------
# $> ruby otp.rb WE CANT STOP THIS THING WEVE STARTED
#
# Alphabet          A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z
#                   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26
#
# Message           W  E     C  A  N  T     S  T  O  P     T  H  I  S     T  H  I  N  G     W  E  V  E     S  T  A  R  T  E  D
#                  22  4 26  2  0 13 19 26 18 19 14 15 26 19  7  8 18 26 19  7  8 13  6 26 22  4 21  4 26 18 19  0 17 19  4  3
#
# Key               K  S  Q  D  M  Q  V  I  T  G  T  I  R  N  D  G  R  T  V  P  F  Q     Y  K  J  U  Y  H  T  G  S  W  R  H  Q  A  Y  V  M  G  Y  B  Z  R  S  C  G
#                  10 18 16  3 12 16 21  8 19  6 19  8 17 13  3  6 17 19 21 15  5 16 26 24 10  9 20 24  7 19  6 18 22 17  7 16  0 24 21 12  6 24  1 25 17 18  2  6
#
# Ciphertext        F  W  P  F  M  C  N  H  K  Z  G  X  Q  F  K  O  I  S  N  W  N  C  F  X  F  N  O  B  G  K  Z  S  M  J  L  T     X  U  L  F  X  A  Y  Q  R  B  F
#                   5 22 15  5 12  2 13  7 10 25  6 23 16  5 10 14  8 18 13 22 13  2  5 23  5 13 14  1  6 10 25 18 12  9 11 19 26 23 20 11  5 23  0 24 16 17  1  5
#
# Decrypted         W  E     C  A  N  T     S  T  O  P     T  H  I  S     T  H  I  N  G     W  E  V  E     S  T  A  R  T  E  D
#                  22  4 26  2  0 13 19 26 18 19 14 15 26 19  7  8 18 26 19  7  8 13  6 26 22  4 21  4 26 18 19  0 17 19  4  3 26 26 26 26 26 26 26 26 26 26 26 26
#
# Message      : "WE CANT STOP THIS THING WEVE STARTED"
# Key          : "KSQDMQVITGTIRNDGRTVPFQ YKJUYHTGSWRHQAYVMGYBZRSCG"
# Ciphertext   : "FWPFMCNHKZGXQFKOISNWNCFXFNOBGKZSMJLT XULFXAYQRBF"
# Decrypted    : "WE CANT STOP THIS THING WEVE STARTED            "
