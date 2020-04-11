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

def doEnc ciphername, mode, encrypt, key, iv, iin
    len_in, len_out, out = 0, 0, []
    st = "#{ciphername}-#{key.b.size*8}-#{mode}" # "AES-128-CFB"
    enc = OpenSSL::Cipher.new st
    enc.key = k = key
    enc.iv  = v = iv
    if encrypt
      enc.encrypt()
    else
      enc.decrypt()
    end
    while true
      src = iin.read(10240)
      break unless src
      out << enc.update(src.b)
      len_in += src.b.size
      len_out += out[-1].b.size
    end
    out << enc.final
    len_out += out[-1].b.size
    if $debug
      STDERR.puts([st, k, v, len_in,  out.join.b.size].inspect)
    end
    return len_in, len_out, out
end

def main
    len_in, len_out, dst = doEnc($options[:cipher], $options[:mode], $options[:encrypt], $options[:key], $options[:iv], STDIN)
    if $debug
        STDERR.puts "key:#{$options[:key]} iv:#{$options[:iv]}  src len: #{len_in}  dst len: #{len_out}"
    end
    print(dst.join)
end
main
