# Exclude integration tests by default (require TUN device / root privileges)
# Run with: INTEGRATION=true mix test
if System.get_env("INTEGRATION") == "true" do
  ExUnit.start()
else
  ExUnit.start(exclude: [:integration])
end
