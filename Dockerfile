FROM quay.io/keycloak/keycloak:latest

# Copy realm export if you have one
COPY realm-export.json /opt/keycloak/data/import/

# Set database config and other build options
ENV KC_DB=postgres
ENV KC_DB_URL_HOST=postgres
ENV KC_DB_URL_DATABASE=keycloak
ENV KC_DB_USERNAME=keycloak
ENV KC_DB_PASSWORD=keycloak
ENV KC_DB_SCHEMA=public

# Build the optimized Keycloak server
RUN /opt/keycloak/bin/kc.sh build

# Use the custom startup command when this image runs
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized", "--import-realm"] 