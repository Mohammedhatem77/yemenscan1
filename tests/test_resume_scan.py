import os
import sys
import json
import shutil
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.session import (
    create_scan_session,
    get_status,
    stop_scan_session,
    resume_scan_session,
    get_session_dir
)
from core.runner import mark_scan_cancelled, is_scan_cancelled, clear_scan_cancelled
from core.pipeline import run_full_pipeline

def test_session_stop_and_resume_state():
    test_domain = "resume-test.example.com"
    scan_id = create_scan_session(test_domain)
    
    # Verify initial state
    st = get_status(scan_id)
    assert st is not None
    assert st["status"] == "queued"
    assert not is_scan_cancelled(scan_id)
    
    # Stop the scan
    stop_scan_session(scan_id)
    st = get_status(scan_id)
    assert st["status"] == "stopped"
    assert is_scan_cancelled(scan_id)
    
    # Resume the scan
    res = resume_scan_session(scan_id)
    assert res is True
    st = get_status(scan_id)
    assert st["status"] == "running"
    assert not st["is_completed"]
    assert not is_scan_cancelled(scan_id)
    assert any("تم استئناف عملية الفحص" in log for log in st["logs"])
    
    # Cleanup
    session_dir = get_session_dir(scan_id)
    if os.path.exists(session_dir):
        shutil.rmtree(session_dir, ignore_errors=True)

def test_pipeline_artifact_aware_resume():
    test_domain = "resume-artifact.example.com"
    scan_id = create_scan_session(test_domain)
    session_dir = get_session_dir(scan_id)
    
    # Simulate prior completion of Subfinder and Naabu
    subdomains = ["api.resume-artifact.example.com", "admin.resume-artifact.example.com"]
    with open(os.path.join(session_dir, "subdomains.txt"), "w", encoding="utf-8") as f:
        for s in subdomains:
            f.write(f"{s}\n")
            
    with open(os.path.join(session_dir, "subfinder_metadata.json"), "w", encoding="utf-8") as f:
        json.dump({
            "tool": "subfinder",
            "status": "completed",
            "valid_count": len(subdomains)
        }, f)
        
    ports = ["api.resume-artifact.example.com:443", "admin.resume-artifact.example.com:8443"]
    with open(os.path.join(session_dir, "ports.txt"), "w", encoding="utf-8") as f:
        for p in ports:
            f.write(f"{p}\n")
            
    with open(os.path.join(session_dir, "naabu_metadata.json"), "w", encoding="utf-8") as f:
        json.dump({
            "tool": "naabu",
            "status": "completed",
            "open_ports_count": len(ports)
        }, f)

    # Simulate stopping at this point
    stop_scan_session(scan_id)
    assert is_scan_cancelled(scan_id)

    # Resume the session
    resume_scan_session(scan_id)
    assert not is_scan_cancelled(scan_id)
    
    # Read status and verify logs
    st = get_status(scan_id)
    assert st["status"] == "running"

    # Cleanup
    if os.path.exists(session_dir):
        shutil.rmtree(session_dir, ignore_errors=True)

def test_templates_resume_elements():
    index_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates", "index.html")
    assert os.path.exists(index_path)
    
    with open(index_path, "r", encoding="utf-8") as f:
        html = f.read()
        
    # Check button IDs
    assert 'id="resumeScanBtn"' in html
    assert 'id="progressResumeBtn"' in html
    
    # Check button styling
    assert '.resume-btn' in html
    assert '.resume-badge-btn' in html
    
    # Check JS functions
    assert 'resumeCurrentScan()' in html
    assert 'showResumeButton(' in html
    assert 'POST' in html
    assert '/resume' in html

def test_resume_endpoint():
    from fastapi import BackgroundTasks
    from main import resume_scan_endpoint
    from database import SessionLocal
    
    test_domain = "resume-endpoint.example.com"
    scan_id = create_scan_session(test_domain)
    stop_scan_session(scan_id)
    
    bg = BackgroundTasks()
    with SessionLocal() as db:
        res = resume_scan_endpoint(background_tasks=bg, scan_id=scan_id, db=db)
        assert res["status"] == "success"
        assert res["scan_id"] == scan_id
        assert "استئناف" in res["message"]
        
    st = get_status(scan_id)
    assert st["status"] == "running"
    
    session_dir = get_session_dir(scan_id)
    if os.path.exists(session_dir):
        shutil.rmtree(session_dir, ignore_errors=True)

if __name__ == "__main__":
    test_session_stop_and_resume_state()
    test_pipeline_artifact_aware_resume()
    test_templates_resume_elements()
    test_resume_endpoint()
    print("ALL RESUME TESTS PASSED SUCCESSFULLY!")
