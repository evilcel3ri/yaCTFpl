require "json"

# This is a small scripts that will compare some of data you might have parsed
# out from log files against a json file.

def find_match(arr, line)
  if arr.include?(line)
    return true
  end
end

def cleaning(str)
  return str.gsub("\n", "")
end

def build_array(key, json_file)
  arr = []
  json_file[key].each {|line| arr.append(line)}
  return arr
end

def look_into_file(file_name, array)
  File.foreach(file_name) do |x|
    if !find_match(array, cleaning(x))
      puts file_name
      puts x
    end
  end
end

puts "running..."
json = File.open("auth.json")
data = JSON.load(json) 

serials = build_array("serial", data)
look_into_file("serials", serials)

products = build_array("prod", data)
look_into_file("products", products)

manufacturers = build_array("manufact", data)
look_into_file("manus", manufacturers)
