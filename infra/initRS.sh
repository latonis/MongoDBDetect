docker run --rm -d -p 27017:27017 -h $(hostname) --name mongo mongo:latest --replSet=rs0 && sleep 5 && docker exec mongo mongosh --eval "rs.initiate();"