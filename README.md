# Unity CA

A full lab, development, and test **Certificate Authority (CA) generator** leveraging **Elliptic Curve Digital Signature Algorithm (ECDSA)** with a modern web-based GUI.

This project allows users to quickly spin up their own CA environment for **testing, development, or learning purposes**, without the complexity of production-grade CA setups.

---

## Docker Compose Setup

```yaml
version: "3.8"

services:
  unity-ca:
    image: cs64net/unity-ca:v1.0   # point to your Docker Hub image
    container_name: unity-ca
    ports:
      - "8003:5000"           # host:container
    environment:
      # Set password to enable auth. If omitted/empty => auth disabled.
      - UNITY_CA_PASSWORD=<LoginPassword>
      - UNITY_CA_SECRET_KEY=<RandomSecret>
      - UNITY_CA_DEBUG=0
    volumes:
      - unity_issued:/data/issued
      - unity_root:/data/root
      - unity_config:/data/config
    restart: unless-stopped

volumes:
  unity_issued:
  unity_root:
  unity_config:
```
---

## Starting the CA

To build and start the container using Docker Compose:

```bash
docker-compose up -d
```

- Access the web GUI at: `http://localhost:8003`  
- View logs with: `docker-compose logs -f unity-ca`  

**Note:** The username is `admin` and the password is what you've set in `UNITY_CA_PASSWORD`.
