Unity CA
A full lab, development, and test Certificate Authority (CA) generator leveraging Elliptic Curve Digital Signature Algorithm (ECDSA) with a modern web-based GUI.
This project allows users to quickly spin up their own CA environment for testing, development, or learning purposes, without the complexity of production-grade CA setups.
Docker Compose Setup
version: "3.8"

services:
  unity-ca:
    build: .
    container_name: unity-ca
    ports:
      - "8111:5000"           # host:container
    environment:
      # Set password to enable authentication. If omitted/empty => auth disabled.
      - UNITY_CA_PASSWORD=<Password-here>
      - UNITY_CA_SECRET_KEY=<SECRET-here>
      - UNITY_CA_DEBUG=0
    volumes:
      - unity_issued:/data/issued
      - unity_root:/data/root
      - unity_config:/data/config
      # optionally mount templates for on-host editing:
      #- ./templates:/app/templates:ro
    restart: unless-stopped

volumes:
  unity_issued:
  unity_root:
  unity_config:
Starting the CA
To build and start the container using Docker Compose:
docker-compose up -d
Access the web GUI at: http://localhost:8111
Logs can be viewed with: docker-compose logs -f unity-ca
