# Use the official Elixir image as base
FROM elixir:1.19.1-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential erlang-dev make \
    git \
    softhsm2 \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy mix files
COPY mix.exs mix.lock ./test_apps/p11ex_bench/

# Install hex and rebar
RUN mix local.hex --force && \
    mix local.rebar --force

# Install dependencies
COPY lib/p11ex ./lib/p11ex

WORKDIR /app/test_apps/p11ex_bench
RUN ls -al . && mix deps.get

# Copy the rest of the application
COPY . .

# Compile the application
RUN ls -al . && mix compile

# Create SoftHSM2 token directory
RUN mkdir -p /var/lib/softhsm/tokens

# Initialize SoftHSM2 token
RUN softhsm2-util --init-token --free --label "Token_0" --pin 1234 --so-pin 12345678

# Expose the port the app runs on
EXPOSE 4000

# Command to run the application
CMD ["mix", "run", "--no-halt"] 
