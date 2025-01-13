# Keycloak Instance

This repository contains a Docker-based setup for running a Keycloak instance with Nginx as a reverse proxy. This setup is intended for local development and testing purposes.

## Prerequisites

- Docker
- Docker Compose

## Setup Instructions

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/BetterGR/keycloak-instance.git
   cd keycloak-instance
   ```

2. **Modify the Hosts File:**

   Add the following line to your hosts file to map `auth.BetterGR.org` to `localhost`:

   - On Windows: `C:\Windows\System32\drivers\etc\hosts`
   - On Linux/macOS: `/etc/hosts`
   ```
   127.0.0.1 auth.BetterGR.org   ```

3. **Start the Services:**

   Use Docker Compose to start the Keycloak and Nginx services:
   ```bash
   docker-compose up   ```

4. **Access Keycloak:**

   Open your web browser and navigate to `http://auth.BetterGR.org`. Log in using the default admin credentials:

   - Username: `admin`
   - Password: `admin`

## Configuration

- **Keycloak Configuration:**
  - The Keycloak service is configured to run in development mode with default admin credentials. You can modify these in the `docker-compose.yml` file.

- **Nginx Configuration:**
  - The Nginx configuration is located in `ngnix/ngnix.conf`. It is set up to forward requests from `auth.BetterGR.org` to the Keycloak service.

## Troubleshooting

- Ensure Docker and Docker Compose are installed and running.
- Verify that the `ngnix.conf` file is correctly placed and accessible.
- Check that the hosts file is correctly configured.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
