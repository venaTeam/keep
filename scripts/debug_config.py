import os

# Mock missing .env
os.environ["AUTH_TYPE"] = "noauth" # Ensure it exists in env if we want to test that, or remove it to test default.
if "AUTH_TYPE" in os.environ:
    del os.environ["AUTH_TYPE"]

try:
    from keep.common.core.config import config
    print(f"Config object: {config}")
    print(f"Type of config: {type(config)}")
    
    auth_type = config("AUTH_TYPE", default="noauth")
    print(f"Auth type raw: {auth_type}")
    print(f"Auth type lower: {auth_type.lower()}")

except Exception as e:
    print(f"Error: {e}")
