import time
import uuid
import jwt
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

# Request schema for verify endpoint
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
        if origin == ALLOWED_ORIGIN:
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

    # Set Access-Control-Allow-Origin ONLY if origin matches exactly
    if origin == ALLOWED_ORIGIN:
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
        return JSONResponse(
            status_code=400, 
            content={"error": "Missing 'values' query parameter"}
        )

    try:
        num_list = [int(val.strip()) for val in values.split(",") if val.strip() != ""]
    except ValueError:
        return JSONResponse(
            status_code=400, 
            content={"error": "All values must be valid integers"}
        )

    if not num_list:
        return JSONResponse(
            status_code=400, 
            content={"error": "No valid numbers found in the values list"}
        )

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
        # Decodes, validates RS256 signature, issuer, audience, and expiry
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
        # Returns 401 on any parsing, expired, tampered, or invalid tokens
        return JSONResponse(
            status_code=401,
            content={"valid": False}
        )
