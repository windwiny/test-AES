#!/usr/bin/env ruby

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

if !File.file? %{#{__dir__}/goenc}
  system "go build -o goenc goenc.go"
end




class String
  # colorization
  def colorize(color_code)
    "\e[#{color_code}m#{self}\e[0m"
  end

  def red
    colorize(31)
  end

  def green
    colorize(32)
  end

  def yellow
    colorize(33)
  end

  def blue
    colorize(34)
  end

  def pink
    colorize(35)
  end

  def light_blue
    colorize(36)
  end
end
def color_puts cmd
  puts cmd.light_blue
end



%w{AES}.each do |cipher|
    %w{CFB CTR OFB}.each do |mode|
        STDERR.puts "---------- #{cipher} --- #{mode} -----------------------------"
        llen = 16
        key = "234asdfaasfdasfdsfsdfs234324324324234234324dffsdff".b[0...llen]
        iv = "kdl3ialasfasd23432432432f4asfasdfs0mernzx;".b[0...llen]
        key = key.b.split(//).map{|e| format "%02X" % e.ord }.join
        iv  = iv.b.split(//).map{|e| format "%02X" % e.ord }.join

        c1=%{ruby #{__dir__}/rubyenc.rb --enc #{cipher} --mode #{mode} -e --key #{key} --iv #{iv} |}
        c2=%{ruby #{__dir__}/rubyenc.rb --enc #{cipher} --mode #{mode} -d --key #{key} --iv #{iv} |} if $reverse
        cmd =  %{ cat '#{$file}' | #{c1} #{c2} md5sum - }
        color_puts cmd
        system cmd

        c1=%{#{__dir__}/goenc --enc #{cipher} --mode #{mode} -e=true --key #{key} --iv #{iv} |}
        c2=%{#{__dir__}/goenc --enc #{cipher} --mode #{mode} -e=false --key #{key} --iv #{iv} |} if $reverse
        cmd =  %{ cat '#{$file}' | #{c1} #{c2} md5sum - }
        color_puts cmd
        system cmd

        c1=%{openssl enc -#{cipher.downcase}-#{llen*8}-#{mode.downcase} -K #{key} -iv #{iv} |}
        c2=%{openssl enc -d -#{cipher.downcase}-#{llen*8}-#{mode.downcase} -K #{key} -iv #{iv} |} if $reverse
        cmd =  %{ cat '#{$file}' | #{c1} #{c2} md5sum - }
        color_puts cmd
        system cmd

    end
end

