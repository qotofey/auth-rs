FROM rust:alpine AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo fetch && cargo build --release

COPY src migrations ./
RUN cargo build --release

FROM debian:stable-slim

WORKDIR /app

COPY --from=builder /app/target/release/auth /app/auth

CMD ["./auth"]
