#/bin/bash
docker load -i images/ghostwriter_production_collab_server
docker load -i images/ghostwriter_production_django
docker load -i images/ghostwriter_production_graphql
docker load -i images/ghostwriter_production_nginx
docker load -i images/ghostwriter_production_postgres
docker load -i images/ghostwriter_production_queue
docker load -i images/ghostwriter_production_redis

tar -xzf data.tar.gz -C src/data

docker compose -f production.yml up -d
./ghostwriter-cli-linux up

# git clone https://github.com/GhostManager/Ghostwriter.git
# cd Ghostwriter
# ./ghostwriter-cli-linux install