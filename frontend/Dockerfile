FROM rust:latest as wasm-builder

WORKDIR /app

# Install build dependencies (clang, etc.) needed for secp256k1-sys
RUN apt-get update && apt-get install -y \
    clang \
    build-essential \
    binaryen \
    && rm -rf /var/lib/apt/lists/*

# Install wasm-pack
RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Copy Cargo files
COPY Cargo.toml Cargo.lock* ./
COPY build.rs ./
COPY .cargo ./.cargo

# Copy source code
COPY src ./src

# Build WASM package
RUN wasm-pack build --target web --out-dir pkg

# Nginx stage
FROM nginx:alpine


RUN rm /etc/nginx/conf.d/default.conf

COPY examples/* /usr/share/nginx/html/

COPY --from=wasm-builder /app/pkg /usr/share/nginx/html/pkg

COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf