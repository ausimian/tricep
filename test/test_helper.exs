# Exclude integration tests by default (require TUN device / root privileges)
# Run with: mix test --include integration
ExUnit.start(exclude: [:integration])
