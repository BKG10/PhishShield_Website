from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from model_predictor import ModelPredictor
from typing import List, Dict
from datetime import datetime
from urllib.parse import urlparse
import json
import os

app = FastAPI()

# Enhanced CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
    expose_headers=["*"],  # Expose all headers
    max_age=600,  # Cache preflight requests for 10 minutes
)

# Initialize model predictor
predictor = ModelPredictor()

# List of trusted websites
TRUSTED_DOMAINS = [
    'google.com',
    'openai.com',
    'chatgpt.com',
    'chat.openai.com',
    'microsoft.com',
    'github.com',
    'stackoverflow.com',
    'linkedin.com',
    'facebook.com',
    'twitter.com',
    'youtube.com',
    'amazon.com',
    'netflix.com',
    'spotify.com',
    'reddit.com',
    'wikipedia.org',
    'medium.com',
    'quora.com',
    'dropbox.com',
    'slack.com',
    'discord.com',
    'zoom.us',
    'mozilla.org',
    'apple.com',
    'adobe.com',
    'cloudflare.com'
]

# Store scan history
scan_history: List[Dict] = []

# Statistics storage
stats = {
    "daily_stats": {},
    "response_times": []
}

def get_domain(url: str) -> str:
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain and parsed_url.path:
            # Handle URLs without protocol
            domain = urlparse(f"https://{url}").netloc
        return domain
    except Exception:
        return url

def is_trusted_domain(domain: str) -> bool:
    return any(trusted_domain in domain for trusted_domain in TRUSTED_DOMAINS)

def get_today_stats():
    today = datetime.now().date().isoformat()
    if today not in stats["daily_stats"]:
        stats["daily_stats"][today] = {
            "urls_scanned": 0,
            "threats_blocked": 0
        }
    return stats["daily_stats"][today]

class URLInput(BaseModel):
    url: str

@app.post("/predict_url")
async def predict_url(input_data: URLInput):
    start_time = datetime.now()
    
    try:
        url = input_data.url
        domain = get_domain(url)

        # Check if domain is trusted
        if is_trusted_domain(domain):
            result = {
                "url": url,
                "isPhishing": False,
                "timestamp": datetime.now().isoformat(),
                "message": "URL is from a trusted domain"
            }
        else:
            # Use model to predict
            prediction_result = predictor.predict_from_url(url)
            
            if "error" in prediction_result:
                raise HTTPException(status_code=500, detail=prediction_result["error"])
                
            result = {
                "url": url,
                "isPhishing": prediction_result["prediction"] == 0,  # 0 is phishing, 1 is legitimate
                "timestamp": datetime.now().isoformat(),
                "message": f"URL is {prediction_result['result']}",
                "features": prediction_result.get("features", {})
            }

        # Add to scan history
        scan_history.insert(0, result)
        
        # Keep only last 10 scans
        if len(scan_history) > 10:
            scan_history.pop()
            
        # Update statistics
        today_stats = get_today_stats()
        today_stats["urls_scanned"] += 1
        if result["isPhishing"]:
            today_stats["threats_blocked"] += 1
        
        # Track response time
        response_time = (datetime.now() - start_time).total_seconds() * 1000
        stats["response_times"].append(response_time)
        # Keep only last 100 response times
        stats["response_times"] = stats["response_times"][-100:]
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/history")
async def get_history():
    return scan_history

@app.delete("/history")
async def clear_history():
    try:
        scan_history.clear()
        return {"message": "History cleared successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/extension_stats")
async def get_extension_stats():
    today_stats = get_today_stats()
    avg_response_time = sum(stats["response_times"][-100:]) / len(stats["response_times"][-100:]) if stats["response_times"] else 0
    
    return {
        "urls_scanned_today": today_stats["urls_scanned"],
        "threats_blocked_today": today_stats["threats_blocked"],
        "avg_response_time": round(avg_response_time)
    }

@app.get("/")
async def root():
    return {"message": "PhishShield API is running"}

# Add OPTIONS handler for CORS preflight requests
@app.options("/{path:path}")
async def options_handler():
    return {"message": "OK"} 