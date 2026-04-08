# -------------------------
# Dev stage (Vite dev server)
# -------------------------
    FROM node:20-alpine AS dev

    WORKDIR /app
    COPY package*.json ./
    RUN npm ci
    COPY . .
    
    # Vite dev server
    EXPOSE 5173
    CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]
    
    
    # -------------------------
    # Build stage (Vite production build)
    # -------------------------
    FROM node:20-alpine AS build
    
    # Make Vite env vars available at build time
    ARG VITE_INGEST_KEY
    ARG VITE_FIREBASE_API_KEY
    ARG VITE_FIREBASE_AUTH_DOMAIN
    ARG VITE_FIREBASE_APP_ID
    
    ENV VITE_INGEST_KEY=${VITE_INGEST_KEY} \
        VITE_FIREBASE_API_KEY=${VITE_FIREBASE_API_KEY} \
        VITE_FIREBASE_AUTH_DOMAIN=${VITE_FIREBASE_AUTH_DOMAIN} \
        VITE_FIREBASE_APP_ID=${VITE_FIREBASE_APP_ID}
    
    WORKDIR /app
    COPY package*.json ./
    RUN npm ci
    COPY . .
    RUN npm run build
    
    
    # -------------------------
    # Runtime stage (Nginx serves /dist)
    # -------------------------
    FROM nginx:1.27-alpine AS serve
    COPY nginx.conf /etc/nginx/conf.d/default.conf
    COPY --from=build /app/dist /usr/share/nginx/html
    EXPOSE 80
    