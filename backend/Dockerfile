FROM rust:latest as builder

WORKDIR /app

# Install build dependencies needed for secp256k1-sys
RUN apt-get update && apt-get install -y \
    clang \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy Cargo files
COPY Cargo.toml Cargo.lock* ./
COPY build.rs ./
COPY .cargo ./.cargo

# Copy source code
COPY src ./src

# Build the backend binary
RUN cargo build --bin solver --features backend --release --target x86_64-unknown-linux-gnu

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary
COPY --from=builder /app/target/x86_64-unknown-linux-gnu/release/solver /app/solver

EXPOSE 3000

ENV PORT=3000
ENV HOST=0.0.0.0

CMD ["./solver"]

