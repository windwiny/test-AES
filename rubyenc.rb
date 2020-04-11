require 'openssl'
require 'optparse'

$debug = false
$options = Struct.new(:debug,:cipher,:mode,:encrypt,:key,:iv).new()
$options[:debug]=false
$options[:encrypt]=false
OptionParser.new do |opts|
  opts.banner = "Usage: rubyenc.rb [options]"

  opts.on( "--debug", "DEBUG mode") do |v|
    $options[:debug] = $debug = v
  end
  opts.on( "-e", " encrypt ") do |v|
    $options[:encrypt] = v
  end
  opts.on( "-d", " decrypt") do |v|
    $options[:encrypt] = false
  end
  opts.on( "--enc=CIPLHERNAME", "ciphername AES|DES") do |v|
    if !['AES','DES'].include? v
        STDERR.puts "cipher support AES/DES, unknow \"#{v}\""
        exit(1)
    end
    $options[:cipher] = v
  end
  opts.on( "--mode=MODE", "cipher mode CFB|CTR|OFB") do |v|
    if !["CBC", "CFB", "CTR", "OFB"].include? v
        STDERR.puts "cipher mode support CBC|CFB|CTR|OFB, unknow\"#{v}\""
        exit(1)
    end
    $options[:mode] = v
  end
  opts.on( "--key=KEY", "Key= 16|24|32 bytes") do |v|
    if ![16,24,32].include? v.b.size
        STDERR.puts "key size not 16/24/32 bytes"
        exit(1)
    end
    $options[:key] = v
  end
  opts.on("--iv=IV", "IV= 16 bytes") do |v|
    if 16 != v.b.size
        STDERR.puts "iv size not 16 bytes"
        exit(1)
    end
    $options[:iv] = v
  end
end.parse!

if !$debug
  if ENV['DEBUG'] && !['0','FALSE'].include?(ENV['DEBUG'])
    $options[:debug] = $debug = true
  end
end

if $debug
  STDERR.puts $options.inspect
  STDERR.puts ARGV.inspect
end

def doEnc ciphername, mode, encrypt, key, iv, iin, iout
    len_in, len_out = 0, 0
    st = "#{ciphername}-#{key.b.size*8}-#{mode}" # "AES-128-CFB"
    enc = OpenSSL::Cipher.new st
    enc.key = key
    enc.iv  = iv
    if encrypt
      enc.encrypt()
    else
      enc.decrypt()
    end
    while true
      src = iin.read(10240)
      break unless src
      msg = enc.update(src.b)
      len_in += src.b.size
      len_out += msg.b.size
      iout.write(msg)
    end
    msg = enc.final
    len_out += msg.b.size
    iout.write(msg)
    if $debug
      STDERR.puts "key:#{key} iv:#{iv}  src len: #{len_in}  dst len: #{len_out}"
    end
    return len_in, len_out
end

def main
    len_in, len_out = doEnc($options[:cipher], $options[:mode], $options[:encrypt], $options[:key], $options[:iv], STDIN, STDOUT)
    # print(dst.join)
end
main
