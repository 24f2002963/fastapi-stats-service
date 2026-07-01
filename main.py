import time
import uuid
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

app = FastAPI()

ALLOWED_ORIGIN = "https://dash-t1j7qz.example.com"
EMAIL = "24f2002963@ds.study.iitm.ac.in"

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
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "*"
        
        # Inject required headers
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
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"

    # Apply mandatory middleware headers to the response
    process_time = time.perf_counter() - start_time
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.6f}"

    return response

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
