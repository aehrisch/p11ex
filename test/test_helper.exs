# Set PKCS11_MODULE to SoftHSM2 module path, depending on OS
if System.get_env("PKCS11_MODULE") == nil do
  softhsm_path = case :os.type() do
    {:unix, :darwin} -> "/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so"
    {:unix, :linux} -> "/usr/lib/softhsm/libsofthsm2.so"
    _ -> raise "Unsupported operating system"
  end

  System.put_env("PKCS11_MODULE", softhsm_path)
end

ExUnit.start()
ExUnit.configure(formatters: [JUnitFormatter, ExUnit.CLIFormatter])
