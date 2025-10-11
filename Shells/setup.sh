git clone https://github.com/0dayCTF/reverse-shell-generator
cd reverse-shell-generator
docker build -t reverse_shell_generator .
docker run -d -p 3003:80 reverse_shell_generator