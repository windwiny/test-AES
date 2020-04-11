require 'shellwords'
require 'openssl'

$file = nil
ARGV.each do |fn|
    if File.file? fn
        $file = fn
        break
    end
end
if !$file 
    STDERR.puts " ruby test.rb  file_name "
    exit(3)
end

$reverse = ARGV.include?('-r')

%w{AES}.each do |cipher|
    %w{CFB CTR OFB}.each do |mode|
        STDERR.puts "---------- #{cipher} --- #{mode} -----------------------------"
        llen = 16
        key = "234asdfaasfdasfdsfsdfs234324324324234234324dffsdff"[0...llen]
        iv = "kdl3ialasfasd23432432432f4asfasdfs0mernzx;"[0...llen]

        puts '-- ruby --'
        c1=%{ruby #{__dir__}/rubyenc.rb --enc #{cipher} --mode #{mode} -e --key '#{key}' --iv '#{iv}' |}
        c2=%{ruby #{__dir__}/rubyenc.rb --enc #{cipher} --mode #{mode} -d --key '#{key}' --iv '#{iv}' |} if $reverse
        cmd =  %{ cat '#{$file}' | #{c1} #{c2} md5sum - }
        puts cmd
        system cmd

        puts '-- golang --'
        c1=%{#{__dir__}/goenc --enc #{cipher} --mode #{mode} -e --key '#{key}' --iv '#{iv}' |}
        c2=%{#{__dir__}/goenc --enc #{cipher} --mode #{mode} -e=false --key '#{key}' --iv '#{iv}' |} if $reverse
        cmd =  %{ cat '#{$file}' | #{c1} #{c2} md5sum - }
        puts cmd
        system cmd

        puts '-- openssl --'
        key2 = key.split(//).map{|e| format "%02X" % e.ord }.join
        iv2  = iv.split(//).map{|e| format "%02X" % e.ord }.join
        c1=%{openssl enc -#{cipher.downcase}-#{llen*8}-#{mode.downcase} -K '#{key2}' -iv '#{iv2}' |}
        c2=%{openssl enc -d -#{cipher.downcase}-#{llen*8}-#{mode.downcase} -K '#{key2}' -iv '#{iv2}' |} if $reverse
        cmd =  %{ cat '#{$file}' | #{c1} #{c2} md5sum - }
        puts cmd
        system cmd

    end
end
