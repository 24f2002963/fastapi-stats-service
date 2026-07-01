import os
import time
import uuid
import jwt
import yaml
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()

# Assigned Values
ALLOWED_ORIGIN = "https://dash-t1j7qz.example.com"
EMAIL = "24f2002963@ds.study.iitm.ac.in"

# IdP RS256 Public Key
IDP_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

class TokenVerifyRequest(BaseModel):
    token: str

@app.middleware("http")
async def process_request(request: Request, call_next):
    start_time = time.perf_counter()
    request_id = str(uuid.uuid4())
    origin = request.headers.get("origin")

    # Manually handle Preflight OPTIONS requests
    if request.method == "OPTIONS":
        response = Response(status_code=204)
        if request.url.path == "/effective-config":
            # Allow any origin for effective-config CORS compliance
            response.headers["Access-Control-Allow-Origin"] = origin if origin else "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "*"
        elif origin == ALLOWED_ORIGIN:
            response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "*"
        
        process_time = time.perf_counter() - start_time
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{process_time:.6f}"
        return response

    # Process standard requests (GET, POST, etc.)
    try:
        response = await call_next(request)
    except Exception:
        response = JSONResponse(content={"error": "Internal Server Error"}, status_code=500)

    # Set CORS Headers based on path rules
    if request.url.path == "/effective-config":
        response.headers["Access-Control-Allow-Origin"] = origin if origin else "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"
    elif origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"

    # Apply mandatory middleware headers to the response
    process_time = time.perf_counter() - start_time
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.6f}"

    return response

# --- Question 1: Stats Endpoint ---
@app.get("/stats")
async def get_stats(values: str = None):
    if not values:
        return JSONResponse(status_code=400, content={"error": "Missing 'values' query parameter"})

    try:
        num_list = [int(val.strip()) for val in values.split(",") if val.strip() != ""]
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "All values must be valid integers"})

    if not num_list:
        return JSONResponse(status_code=400, content={"error": "No valid numbers found in the values list"})

    count = len(num_list)
    total_sum = sum(num_list)
    minimum = min(num_list)
    maximum = max(num_list)
    mean = total_sum / count

    return {
        "email": EMAIL,
        "count": count,
        "sum": total_sum,
        "min": minimum,
        "max": maximum,
        "mean": mean
    }

# --- Question 2: JWT Verification Endpoint ---
@app.post("/verify")
async def verify_token(request_data: TokenVerifyRequest):
    try:
        payload = jwt.decode(
            request_data.token,
            IDP_PUBLIC_KEY,
            algorithms=["RS256"],
            audience="tds-441ce1wy.apps.exam.local",
            issuer="https://idp.exam.local"
        )
        return {
            "valid": True,
            "email": payload.get("email"),
            "sub": payload.get("sub"),
            "aud": payload.get("aud")
        }
    except Exception:
        return JSONResponse(status_code=401, content={"valid": False})

# --- Question 3: Effective Configuration Endpoint ---
@app.get("/effective-config")
async def get_effective_config(request: Request):
    # 1. Defaults Layer
    merged = {
        "port": "8000",
        "workers": "1",
        "debug": "false",
        "log_level": "info",
        "api_key": "default-secret-000"
    }

    # 2. YAML Layer (config.development.yaml)
    yaml_config = {"log_level": "error"}  # Fallback default
    if os.path.exists("config.development.yaml"):
        try:
            with open("config.development.yaml", "r") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    for k, v in loaded.items():
                        yaml_config[k.lower()] = str(v)
        except Exception:
            pass
    for k, v in yaml_config.items():
        merged[k] = v

    # 3. .env Layer
    env_config = {"NUM_WORKERS": "3", "APP_DEBUG": "false"}  # Fallback default
    if os.path.exists(".env"):
        try:
            with open(".env", "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, val = line.split("=", 1)
                        env_config[key.strip()] = val.strip()
        except Exception:
            pass

    env_mapped = {}
    for k, v in env_config.items():
        val_clean = v.strip("'\"")
        if k == "NUM_WORKERS":
            env_mapped["workers"] = val_clean
        elif k.startswith("APP_"):
            base_key = k[4:].lower()
            env_mapped[base_key] = val_clean
        else:
            env_mapped[k.lower()] = val_clean

    for k, v in env_mapped.items():
        merged[k] = v

    # 4. OS Env Layer (APP_* prefix)
    os_mapped = {}
    for k, v in os.environ.items():
        if k.startswith("APP_"):
            base_key = k[4:].lower()
            if base_key == "num_workers":
                os_mapped["workers"] = v
            else:
                os_mapped[base_key] = v

    for k, v in os_mapped.items():
        merged[k] = v

    # 5. CLI Overrides (?set=key=value)
    cli_overrides = {}
    for key, value in request.query_params.multi_items():
        if key == "set":
            if "=" in value:
                k, v = value.split("=", 1)
                k = k.strip().lower()
                if k == "num_workers":
                    cli_overrides["workers"] = v.strip()
                else:
                    cli_overrides[k] = v.strip()

    for k, v in cli_overrides.items():
        merged[k] = v

    # --- Type Coercion Rules ---
    final_config = {}

    # port -> int
    try:
        final_config["port"] = int(merged.get("port"))
    except Exception:
        final_config["port"] = 8000

    # workers -> int
    try:
        final_config["workers"] = int(merged.get("workers"))
    except Exception:
        final_config["workers"] = 1

    # debug -> bool (true/1/yes/on case-insensitive = true)
    def to_bool(val):
        if isinstance(val, bool):
            return val
        s = str(val).strip().lower()
        return s in ("true", "1", "yes", "on")

    final_config["debug"] = to_bool(merged.get("debug"))

    # log_level and other keys -> string
    final_config["log_level"] = str(merged.get("log_level", "info"))

    # Masking api_key
    final_config["api_key"] = "****"

    return final_config
