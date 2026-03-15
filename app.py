"""
Honeypot Web Application
FastAPI-based deception layer that mimics a vulnerable web application.
"""

from typing import Optional
from uuid import uuid4
from datetime import datetime

from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from llm_engine import generate_response
from analyzer import analyze_request
from logger import log_attack
from correlation_engine import track_attack_action, is_coordinated_attack
from threat_intel import analyze_threat, get_threat_level
from deception_engine import check_fake_security

# Advanced features
from ml_classifier import train_ml_classifier, predict_attack_type, detect_anomaly, track_credential_attempt
from external_threat_intel import lookup_threat_intel, add_threat, configure_threat_intel
from dashboard import add_attack_to_dashboard, broadcast_attack, broadcast_stats, get_active_connections
from counter_intelligence import poison_tool_response, fingerprint_attacker, inject_fake_vulnerability, add_evasion_techniques
from fingerprinting import track_browser_fingerprint, find_related_attackers, get_fingerprinting_script
from alerts import send_attack_alert, send_brute_force_alert, send_coordinated_attack_alert, send_anomaly_alert, send_threat_ip_alert, configure_alerts, AlertSeverity
from demo_dashboard import get_demo_dashboard_html, update_demo_attack, update_demo_llm_thinking, update_demo_analysis, update_demo_threat_intel, update_demo_behavioral

# NEW: Hackathon Enhancement Modules
from attack_predictor import track_attack_for_prediction, get_attack_prediction, get_prediction_summary
from mitre_mapper import map_attack_to_mitre, get_attacker_ttps, get_mitre_matrix, match_to_apt_groups
from forensic_timeline import record_attack_event, record_canary_extraction, record_tool_detection, get_attack_timeline, generate_replay_script, generate_attack_narrative, get_timeline_html
from canary_analytics import register_canary_token, record_canary_usage, get_canary_journey, get_canary_effectiveness, get_attacker_canaries, get_canary_dashboard_data
from adaptive_deception import get_deception_strategy, adapt_response
from threat_sharing import generate_iocs, generate_stix_bundle, generate_threat_report
from playbook_generator import generate_incident_playbook, generate_sigma_rule
from export_engine import export_json, export_csv, export_attacks


# =========================
# APPLICATION SETUP
# =========================
app = FastAPI(
    title="Honeypot Application",
    description="AI-powered deception honeypot",
    version="1.0.0"
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize templates
templates = Jinja2Templates(directory="templates")


# =========================
# CONSTANTS
# =========================
ATTACKER_ID_COOKIE = "attacker_id"


# =========================
# HELPER FUNCTIONS
# =========================
def get_attacker_id(request: Request) -> str:
    """
    Retrieve or generate attacker tracking ID.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Unique attacker identifier (existing or newly generated)
    """
    attacker_id = request.cookies.get(ATTACKER_ID_COOKIE)
    if not attacker_id:
        attacker_id = uuid4().hex
    return attacker_id


def set_attacker_cookie(response: Response, attacker_id: str) -> None:
    """
    Set attacker tracking cookie on response.
    
    Args:
        response: FastAPI response object
        attacker_id: Unique attacker identifier
    """
    response.set_cookie(
        key=ATTACKER_ID_COOKIE,
        value=attacker_id,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax"
    )


def create_response(content: str, attacker_id: str) -> Response:
    """
    Create appropriate response based on content type.
    
    Args:
        content: Response content from honeypot engine
        attacker_id: Unique attacker identifier
        
    Returns:
        HTMLResponse or PlainTextResponse with attacker cookie set
    """
    # Detect HTML content
    if content.lstrip().startswith("<!DOCTYPE html") or content.lstrip().startswith("<html"):
        response = HTMLResponse(content=content)
    else:
        response = PlainTextResponse(content=content)
    
    set_attacker_cookie(response, attacker_id)
    return response


def get_mitre_summary(attacker_id: str) -> dict:
    """
    Get MITRE ATT&CK summary for attacker.
    Wrapper function for WebSocket broadcasting.
    """
    try:
        ttp_data = get_attacker_ttps(attacker_id)
        
        # Check if there's an error or no data
        if "error" in ttp_data:
            return {"techniques": [], "count": 0}
        
        # Flatten tactics_breakdown into a simple techniques array
        techniques = []
        if "tactics_breakdown" in ttp_data:
            for tactic_name, tactic_techniques in ttp_data["tactics_breakdown"].items():
                for tech in tactic_techniques:
                    techniques.append({
                        "technique_id": tech["technique_id"],
                        "technique_name": tech["technique_name"],
                        "tactic": tactic_name,
                        "confidence": tech.get("confidence", "N/A")
                    })
        
        return {
            "techniques": techniques,
            "count": len(techniques)
        }
    except Exception as e:
        print(f"[ERROR] Failed to get MITRE summary: {e}")
        return {"techniques": [], "count": 0}


def build_payload(request: Request, query_param: Optional[str] = None) -> str:
    """
    Build payload string from request data.
    
    Args:
        request: FastAPI request object
        query_param: Optional specific query parameter to extract
        
    Returns:
        Formatted payload string for analysis
    """
    if query_param is not None:
        return query_param
    
    # Use all query parameters if no specific param provided
    return str(request.query_params)


# =========================
# HONEYPOT ENDPOINTS
# =========================
@app.get("/search", response_class=Response)
async def search_endpoint(request: Request, q: str = "") -> Response:
    """
    Vulnerable search endpoint - primary SQL injection target.
    
    Simulates a search feature that's vulnerable to SQL injection attacks.
    Tracks attacker progression through SQLi exploitation stages.
    
    Args:
        request: FastAPI request object
        q: Search query parameter (attack vector)
        
    Returns:
        Response with fake search results or leaked data
    """
    attacker_id = get_attacker_id(request)
    payload = build_payload(request, query_param=q)
    
    # Get user agent
    user_agent = request.headers.get("user-agent")
    
    # Detect attack type
    attack_type = analyze_request(payload)
    
    # Check fake security measures (warnings but don't block)
    security_warnings = check_fake_security(attacker_id, payload)
    
    # Threat intelligence analysis
    threat_profile = analyze_threat(
        attacker_id=attacker_id,
        ip_address=request.client.host if request.client else None,
        user_agent=user_agent,
        attack_vector=attack_type,
        success=(attack_type != "NORMAL")
    )
    
    # Track attack for correlation
    campaign = track_attack_action(
        attacker_id=attacker_id,
        endpoint="/search",
        vector=attack_type,
        payload=payload,
        success=(attack_type == "SQL Injection"),
        data_leaked=("users" if attack_type == "SQL Injection" else None)
    )
    
    # NEW: Track for attack prediction
    track_attack_for_prediction(attacker_id, attack_type, "/search")
    
    # NEW: Map to MITRE ATT&CK
    mitre_mappings = map_attack_to_mitre(attack_type, payload, attacker_id)
    
    # NEW: Record in forensic timeline
    record_attack_event(
        attacker_id=attacker_id,
        attack_type=attack_type,
        endpoint="/search",
        payload=payload,
        success=(attack_type != "NORMAL")
    )
    
    # Generate honeypot response (now includes behavioral analysis)
    result = generate_response(
        endpoint="/search",
        payload=payload,
        attacker_id=attacker_id,
        user_agent=user_agent
    )
    
    # NEW: Apply adaptive deception
    # Get skill level from behavioral profile (if available)
    from behavioral_analyzer import get_behavioral_profile
    profile = get_behavioral_profile(attacker_id)
    skill_level = profile.skill_level if profile else "intermediate"
    result = adapt_response(result, attacker_id, skill_level)
    
    # Prepend security warnings if any
    if security_warnings:
        result = "\n".join(security_warnings) + "\n\n" + result
    
    # Log the attack with enhanced metadata
    log_attack(
        attacker_id=attacker_id,
        ip=request.client.host if request.client else "unknown",
        endpoint="/search",
        attack_type=attack_type,
        payload=payload,
        llm_response=result
    )
    
    # Broadcast to demo dashboard with LLM reasoning and predictions
    try:
        # Get LLM reasoning steps
        from llm_engine import get_reasoning_steps
        reasoning_steps = get_reasoning_steps(attack_type, payload, attacker_id)
        
        # Get prediction data
        prediction_data = get_prediction_summary(attacker_id)
        
        # Get MITRE mapping
        mitre_data = get_mitre_summary(attacker_id)
        
        # Get behavioral profile with safe attribute access
        try:
            behavioral_data = {
                "skill_level": str(profile.skill_level).split('.')[-1] if profile and hasattr(profile, 'skill_level') else "UNKNOWN",
                "attack_count": getattr(profile, 'attack_count', 1) if profile else 1,
                "attack_types": list(getattr(profile, 'attack_types', {attack_type})) if profile else [attack_type],
                "first_seen": profile.first_seen.isoformat() if profile and hasattr(profile, 'first_seen') else datetime.now().isoformat()
            }
        except Exception as e:
            print(f"[ERROR] Failed to build behavioral_data: {e}")
            behavioral_data = {
                "skill_level": "UNKNOWN",
                "attack_count": 1,
                "attack_types": [attack_type],
                "first_seen": datetime.now().isoformat()
            }
        
        # Get threat intelligence with safe attribute access
        try:
            threat_data = {
                "threat_level": str(threat_profile.threat_level).split('.')[-1] if threat_profile and hasattr(threat_profile, 'threat_level') else "MEDIUM",
                "risk_score": getattr(threat_profile, 'risk_score', 50) if threat_profile else 50,
                "is_persistent": getattr(threat_profile, 'is_persistent', False) if threat_profile else False
            }
        except Exception as e:
            print(f"[ERROR] Failed to build threat_data: {e}")
            threat_data = {
                "threat_level": "MEDIUM",
                "risk_score": 50,
                "is_persistent": False
            }
        
        await broadcast_demo_update({
            "type": "attack",
            "attacker_id": attacker_id,
            "ip": request.client.host if request.client else "unknown",
            "endpoint": "/search",
            "attack_type": attack_type,
            "payload": payload,
            "timestamp": datetime.now().isoformat(),
            "threat_level": str(threat_profile.threat_level).split('.')[-1] if threat_profile else "MEDIUM",
            "skill_level": str(profile.skill_level).split('.')[-1] if profile else "UNKNOWN",
            "llm_reasoning": reasoning_steps,
            "prediction": prediction_data,
            "mitre": mitre_data,
            "behavioral_profile": behavioral_data,
            "threat_intelligence": threat_data
        })
    except Exception as e:
        print(f"[ERROR] Failed to broadcast to demo dashboard: {e}")
    
    # If it's a browser request (HTML in accept header), render template
    if "text/html" in request.headers.get("accept", ""):
        return templates.TemplateResponse("search.html", {
            "request": request,
            "q": q,
            "results": result if attack_type == "SQL Injection" else None,
            "active_page": "search"
        })

    return create_response(result, attacker_id)


@app.get("/admin", response_class=Response)
async def admin_endpoint(request: Request) -> Response:
    """
    Fake admin panel endpoint.
    
    Simulates an admin interface that becomes accessible after
    successful exploitation. Tracks admin actions and data exfiltration.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Response with admin panel content or command results
    """
    attacker_id = get_attacker_id(request)
    payload = build_payload(request)
    
    # Get user agent
    user_agent = request.headers.get("user-agent")
    
    # Detect attack type
    attack_type = analyze_request(payload)
    
    # Threat intelligence analysis
    threat_profile = analyze_threat(
        attacker_id=attacker_id,
        ip_address=request.client.host if request.client else None,
        user_agent=user_agent,
        attack_vector=attack_type
    )
    
    # Track attack for correlation
    campaign = track_attack_action(
        attacker_id=attacker_id,
        endpoint="/admin",
        vector=attack_type,
        payload=payload,
        success=True  # Admin access is always "successful" in honeypot
    )
    
    # Check if coordinated attack
    is_coordinated = is_coordinated_attack(attacker_id)
    
    # Generate honeypot response
    result = generate_response(
        endpoint="/admin",
        payload=payload,
        attacker_id=attacker_id,
        user_agent=user_agent
    )
    
    # Add coordinated attack warning (for realism)
    if is_coordinated:
        result = "[Security Notice: Multiple attack vectors detected]\n\n" + result
    
    # Log the attack
    # Log the attack
    log_attack(
        attacker_id=attacker_id,
        ip=request.client.host if request.client else "unknown",
        endpoint="/admin",
        attack_type=attack_type,
        payload=payload,
        llm_response=result
    )

    # If it's a browser request (HTML in accept header), render template
    if "text/html" in request.headers.get("accept", ""):
        return templates.TemplateResponse("admin.html", {
            "request": request,
            "result": result
        })
    
    return create_response(result, attacker_id)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """
    Landing page - Redirect to login.
    """
    return templates.TemplateResponse("auth.html", {"request": request, "title": "Login", "is_register": False})


@app.get("/login", response_class=HTMLResponse)
async def login(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("auth.html", {"request": request, "title": "Login", "is_register": False})


@app.get("/register", response_class=HTMLResponse)
async def register(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("auth.html", {"request": request, "title": "Register", "is_register": True})


@app.get("/logs", response_class=HTMLResponse)
async def logs(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("page.html", {"request": request, "title": "System Logs", "type": "logs", "active_page": "logs"})


@app.get("/backups", response_class=HTMLResponse)
async def backups(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("page.html", {"request": request, "title": "Backups", "type": "backups", "active_page": "backups"})


@app.get("/timeline", response_class=HTMLResponse)
async def timeline(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("page.html", {"request": request, "title": "Audit Timeline", "type": "timeline", "active_page": "timeline"})


@app.get("/health")
async def health_check() -> dict:
    """
    Health check endpoint for monitoring.
    
    Returns:
        Simple status object
    """
    return {"status": "ok"}


# =========================
# ERROR HANDLERS
# =========================
@app.exception_handler(404)
async def not_found_handler(request: Request, exc) -> PlainTextResponse:
    """
    Custom 404 handler to maintain honeypot illusion.
    
    Returns generic error without revealing it's a honeypot.
    """
    return PlainTextResponse(
        content="404 Not Found",
        status_code=404
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc) -> PlainTextResponse:
    """
    Custom 500 handler to maintain honeypot illusion.
    
    Returns generic error without revealing it's a honeypot.
    """
    return PlainTextResponse(
        content="500 Internal Server Error",
        status_code=500
    )


# =========================
# ADVANCED ENDPOINTS
# =========================
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Real-time attack monitoring dashboard."""
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "active_page": "dashboard"
    })


@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    """WebSocket for real-time dashboard updates."""
    import asyncio
    import json
    
    await websocket.accept()
    get_active_connections().append(websocket)
    
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            if message.get("type") == "get_stats":
                await broadcast_stats()
    except WebSocketDisconnect:
        if websocket in get_active_connections():
            get_active_connections().remove(websocket)


@app.post("/api/fingerprint")
async def fingerprint_api(request: Request):
    """Receive client-side fingerprint data."""
    try:
        client_data = await request.json()
        attacker_id = get_attacker_id(request)
        user_agent = request.headers.get("user-agent", "")
        
        # Track browser fingerprint with client data
        track_browser_fingerprint(
            attacker_id,
            user_agent,
            dict(request.headers),
            request.client.host if request.client else "unknown",
            client_data
        )
        
        return {"status": "ok"}
    except:
        return {"status": "error"}


@app.get("/demo", response_class=HTMLResponse)
async def demonstration_dashboard():
    """Live demonstration dashboard with detailed attack analysis."""
    return get_demo_dashboard_html()


# Global storage for demo WebSocket connections
_demo_connections = []


@app.websocket("/ws/demo")
async def websocket_demo(websocket: WebSocket):
    """WebSocket for demonstration dashboard real-time updates."""
    import asyncio
    import json
    from datetime import datetime
    
    await websocket.accept()
    _demo_connections.append(websocket)
    
    try:
        while True:
            # Keep connection alive
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        if websocket in _demo_connections:
            _demo_connections.remove(websocket)


async def broadcast_demo_update(data: dict):
    """Broadcast update to all demo dashboard connections."""
    disconnected = []
    
    for connection in _demo_connections:
        try:
            await connection.send_json(data)
        except Exception as e:
            print(f"[WARNING] Failed to send to demo dashboard connection: {e}")
            disconnected.append(connection)
    
    # Remove disconnected clients
    for connection in disconnected:
        _demo_connections.remove(connection)


# =========================
# NEW: HACKATHON ENHANCEMENT ENDPOINTS
# =========================
@app.get("/api/prediction/{attacker_id}")
async def get_prediction(attacker_id: str):
    """Get attack prediction for attacker."""
    return get_prediction_summary(attacker_id)


@app.get("/api/mitre/{attacker_id}")
async def get_mitre(attacker_id: str):
    """Get MITRE ATT&CK mapping for attacker."""
    ttps = get_attacker_ttps(attacker_id)
    matrix = get_mitre_matrix(attacker_id)
    apt_matches = match_to_apt_groups(attacker_id)
    
    return {
        "ttps": ttps,
        "matrix": matrix,
        "apt_matches": [{"group": name, "similarity": f"{score:.1%}"} for name, score in apt_matches]
    }


@app.get("/api/timeline/{attacker_id}")
async def get_timeline(attacker_id: str):
    """Get forensic timeline for attacker."""
    timeline = get_attack_timeline(attacker_id)
    if not timeline:
        return {"error": "No timeline data"}
    
    return {
        "attacker_id": attacker_id,
        "duration": str(timeline.get_duration()),
        "total_attacks": timeline.total_attacks,
        "success_rate": f"{timeline.successful_attacks}/{timeline.total_attacks}",
        "attack_rate": f"{timeline.get_attack_rate():.2f}/min",
        "tools_used": timeline.tools_used,
        "endpoints_targeted": timeline.endpoints_targeted
    }


@app.get("/api/timeline/{attacker_id}/replay")
async def get_replay(attacker_id: str, speed: str = "5x"):
    """Get attack replay script."""
    from forensic_timeline import ReplaySpeed
    
    speed_map = {
        "realtime": ReplaySpeed.REALTIME,
        "2x": ReplaySpeed.FAST_2X,
        "5x": ReplaySpeed.FAST_5X,
        "10x": ReplaySpeed.FAST_10X,
        "instant": ReplaySpeed.INSTANT
    }
    
    replay_speed = speed_map.get(speed, ReplaySpeed.FAST_5X)
    return {"replay_script": generate_replay_script(attacker_id, replay_speed)}


@app.get("/api/timeline/{attacker_id}/narrative")
async def get_narrative(attacker_id: str):
    """Get attack narrative."""
    return {"narrative": generate_attack_narrative(attacker_id)}


@app.get("/api/canary/dashboard")
async def canary_dashboard():
    """Get canary analytics dashboard data."""
    return get_canary_dashboard_data()


@app.get("/api/canary/{attacker_id}")
async def get_canary_stats(attacker_id: str):
    """Get canary statistics for attacker."""
    return get_attacker_canaries(attacker_id)


@app.get("/api/canary/effectiveness")
async def canary_effectiveness():
    """Get canary effectiveness report."""
    return get_canary_effectiveness()


@app.get("/api/export/attacks")
async def export_attack_log():
    """Export attack log as CSV."""
    from logger import get_all_attacks
    attacks = get_all_attacks()
    csv_data = export_attacks(attacks)
    
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=attacks.csv"}
    )


@app.get("/api/threat-intel/{attacker_id}/iocs")
async def get_iocs(attacker_id: str):
    """Generate IOCs for attacker."""
    # Get attacker data
    from logger import get_attacker_history
    history = get_attacker_history(attacker_id)
    
    ips = list(set([h.get("ip", "") for h in history if h.get("ip")]))
    attack_types = list(set([h.get("attack_type", "") for h in history if h.get("attack_type")]))
    payloads = [h.get("payload", "") for h in history if h.get("payload")]
    
    return generate_iocs(attacker_id, ips, attack_types, payloads)


@app.get("/api/threat-intel/{attacker_id}/stix")
async def get_stix(attacker_id: str):
    """Generate STIX bundle for attacker."""
    from logger import get_attacker_history
    from behavioral_analyzer import get_behavioral_profile
    
    history = get_attacker_history(attacker_id)
    profile = get_behavioral_profile(attacker_id)
    
    attack_data = {
        "skill_level": profile.skill_level if profile else "unknown",
        "attack_types": list(set([h.get("attack_type", "") for h in history]))
    }
    
    return generate_stix_bundle(attacker_id, attack_data)


@app.get("/api/playbook/{attack_type}")
async def get_playbook(attack_type: str):
    """Generate incident response playbook."""
    attack_details = {
        "severity": "high" if "sql" in attack_type.lower() else "medium",
        "indicators": [f"Attack type: {attack_type}"]
    }
    
    playbook = generate_incident_playbook(attack_type, attack_details)
    
    return Response(
        content=playbook,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename={attack_type}_playbook.md"}
    )


# =========================
# STARTUP/SHUTDOWN HOOKS
# =========================
@app.on_event("startup")
async def startup_event():
    """Initialize honeypot on startup."""
    print("[*] Honeypot application starting...")
    print("[*] Waiting for attackers...")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    print("[*] Honeypot application shutting down...")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
