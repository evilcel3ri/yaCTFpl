# frozen_string_literal: true

ids = []
titles = []
res = []
File.open('ids.txt').each do |line|
  ids << line
end
File.open('titles.txt').each do |t|
  titles << t
end

ids.each do |id|
  titles.each do |title|
    res << "#{id}-#{title}" if ids.find_index(id) == titles.find_index(title)
  end
end

puts res
