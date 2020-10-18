# frozen_string_literal: true

require 'socket'
require 'OpenURI'

puts 'What host?'
host = gets.chomp
host.to_s

puts 'What port?'
port = gets.chomp
port.to_i

puts 'Path?'
path = gets.chomp
path.to_s

open(host) do |f|
  f.each_line { |line| p line }
  p f.base_uri
  p f.content_type
  p f.charset
  p f.content_encoding
  p f.last_modified
end
