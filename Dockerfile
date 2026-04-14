FROM rust:1.78-bookworm AS builder
WORKDIR /work
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /work/target/release/gz-users /app/gz-users
COPY --from=builder /work/config /app/config
EXPOSE 8080
ENV APP_ENV=dev
CMD ["/app/gz-users"]
