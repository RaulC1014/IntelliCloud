# --- build stage ---
    FROM node:20-alpine AS build

    # Make the key available to Vite at build time
    ARG VITE_INGEST_KEY
    ARG VITE_FIREBASE_API_KEY
    ARG VITE_FIREBASE_AUTH_DOMAIN
    ARG VITE_FIREBASE_APP_ID
    ENV VITE_INGEST_KEY=${VITE_INGEST_KEY}
    
    WORKDIR /app
    COPY package*.json ./
    RUN npm ci
    COPY . .
    # Optional: sanity check that the key is visible to the Node process
    # RUN node -e "console.log('VITE_INGEST_KEY present =', !!process.env.VITE_INGEST_KEY)"
    RUN npm run build
    
    # --- runtime stage ---
    FROM nginx:1.27-alpine AS serve
    COPY nginx.conf /etc/nginx/conf.d/default.conf
    COPY --from=build /app/dist /usr/share/nginx/html
    