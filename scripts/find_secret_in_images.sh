xxd -c1 -p image.jpg | tr "\n" " " | sed -n -e 's/.*\( ff d9 \)\(.*\).*/\2/p' | xxd -r -p
