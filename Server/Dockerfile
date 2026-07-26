FROM node@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293

RUN apk add --no-cache openssl \
    && addgroup -S -g 12000 ostrovua-auth \
    && adduser -S -D -H -u 12000 -G ostrovua-auth ostrovua-auth

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy only reviewed runtime code. Certificates, document trust material and
# secret keys are mounted read-only at runtime and never enter an image layer.
COPY server.js appattest.js apns.js passiveauth.js \
     verification_policy.js self_hosted_contract.js biometric_client.js \
     production_verification_store.js auth_security_store.js \
     security_policy.js media_sanitizer.js oauth_identity.js \
     document_ca.js validate_dsc_chain.js ./

RUN mkdir -p /app/uploads \
    && chown 12000:12000 /app/uploads \
    && chmod 0750 /app/uploads

USER 12000:12000

EXPOSE 3001
CMD ["node", "server.js"]
