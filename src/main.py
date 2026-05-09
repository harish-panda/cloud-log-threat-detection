"""
Main FastAPI Application for Cloud Log Threat Detection Framework
"""

import logging
import os
from datetime import datetime
from typing import List, Dict, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from .core.config import settings
from .database.connection import DatabaseConnection, get_db_connection
from .ml.anomaly_detector import ThreatDetectionPipeline
from .parsers.ssh_parser import SSHLogParser, ParsedLogEntry
from .core.version_manager import VersionManager, UpgradeManager, DeploymentTracker
from .core.docker_version_manager import DockerVersionManager, DockerOrchestrator
import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Cloud Log Threat Detection API",
    description="API for detecting threats in SSH logs using machine learning",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables (lazy initialization)
db_connection = None
ssh_parser = SSHLogParser()
threat_pipeline = None
version_manager = VersionManager()
upgrade_manager = UpgradeManager(version_manager)
deployment_tracker = DeploymentTracker()
docker_manager = DockerVersionManager()
docker_orchestrator = DockerOrchestrator(docker_manager)

# Pydantic models
class LogEntry(BaseModel):
    raw_log: str = Field(..., description="Raw SSH log entry")
    source: Optional[str] = Field(None, description="Log source")

class BatchLogEntry(BaseModel):
    logs: List[str] = Field(..., description="List of raw SSH log entries")

class ThreatAlert(BaseModel):
    id: str
    timestamp: datetime
    threat_type: str
    severity: str
    source_ip: Optional[str]
    target_user: Optional[str]
    description: str
    confidence_score: float
    status: str

class SystemStatus(BaseModel):
    status: str
    timestamp: datetime
    model_trained: bool
    database_connected: bool
    total_logs: int
    recent_threats: int

class TrainingRequest(BaseModel):
    days_back: int = Field(7, description="Number of days of historical data for training")

# Stateful initialization functions
def initialize_db_connection():
    """Initialize database connection with error handling"""
    global db_connection
    try:
        db_connection = DatabaseConnection()
        logger.info("Database connection initialized successfully")
        return True
    except Exception as e:
        logger.warning(f"Database connection failed: {e}. Running in degraded mode.")
        return False

def initialize_threat_pipeline():
    """Initialize ML pipeline with error handling"""
    global threat_pipeline
    try:
        if db_connection:
            threat_pipeline = ThreatDetectionPipeline(db_connection)
            logger.info("ML pipeline initialized successfully")
            return True
        else:
            logger.warning("ML pipeline initialization skipped: no database connection")
            return False
    except Exception as e:
        logger.warning(f"ML pipeline initialization failed: {e}. Running in degraded mode.")
        return False

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize components on startup"""
    logger.info("Starting Cloud Log Threat Detection API")
    initialize_db_connection()
    initialize_threat_pipeline()

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down Cloud Log Threat Detection API")
    if db_connection:
        try:
            db_connection.close()
            logger.info("Database connection closed")
        except Exception as e:
            logger.error(f"Error closing database connection: {e}")

# Dependency injection functions (stateful)
def get_db_connection():
    """Get database connection (lazy initialization)"""
    global db_connection
    if db_connection is None:
        initialize_db_connection()
    return db_connection

def get_threat_pipeline():
    """Get ML pipeline (lazy initialization)"""
    global threat_pipeline
    if threat_pipeline is None:
        initialize_threat_pipeline()
    return threat_pipeline

def get_ssh_parser():
    """Get SSH parser (already initialized)"""
    return ssh_parser

def get_version_manager():
    return version_manager

def get_upgrade_manager():
    return upgrade_manager

def get_deployment_tracker():
    return deployment_tracker

def get_docker_manager():
    return docker_manager

def get_docker_orchestrator():
    return docker_orchestrator

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    try:
        # Test database connection
        db = get_db_connection()
        if not db.test_connection():
            logger.error("Database connection failed")
        else:
            logger.info("Database connection successful")
        
        # Load existing ML model
        pipeline = get_threat_pipeline()
        if pipeline.anomaly_detector.is_trained:
            logger.info("ML model loaded successfully")
        else:
            logger.info("ML model not trained - training required")
        
        logger.info("Application startup completed")
        
    except Exception as e:
        logger.error(f"Startup error: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    """Clean up on shutdown"""
    try:
        if db_connection:
            db_connection.close()
        logger.info("Application shutdown completed")
    except Exception as e:
        logger.error(f"Shutdown error: {e}")

# API Endpoints
@app.get("/", response_model=Dict)
async def root():
    """Root endpoint"""
    return {
        "message": "Cloud Log Threat Detection API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        db_status = db_connection.test_connection()
        
        # Check ML model status
        model_status = threat_pipeline.anomaly_detector.is_trained
        
        # Get log count
        total_logs = len(db_connection.get_recent_logs(hours=24, limit=1000))
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "database_connected": db_status,
            "model_trained": model_status,
            "total_logs": total_logs
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

# Version Management Endpoints
@app.get("/api/v1/version")
async def get_version_info(version_manager=Depends(get_version_manager)):
    """Get current version information"""
    try:
        return version_manager.get_version_info()
    except Exception as e:
        logger.error(f"Error getting version info: {e}")
        raise HTTPException(status_code=500, detail="Error getting version info")

@app.post("/api/v1/version/increment")
async def increment_version(
    version_type: str = "patch",
    changes: List[str] = None,
    version_manager=Depends(get_version_manager)
):
    """Increment version number"""
    try:
        if version_type not in ["major", "minor", "patch"]:
            raise HTTPException(status_code=400, detail="Invalid version type. Must be major, minor, or patch")
        
        new_version = version_manager.increment_version(version_type, changes)
        return {
            "success": True,
            "new_version": new_version.version,
            "message": f"Version incremented to {new_version.version}"
        }
    except Exception as e:
        logger.error(f"Error incrementing version: {e}")
        raise HTTPException(status_code=500, detail="Error incrementing version")

@app.post("/api/v1/backup/create")
async def create_backup(
    backup_name: str = None,
    version_manager=Depends(get_version_manager)
):
    """Create application backup"""
    try:
        backup_path = version_manager.create_backup(backup_name)
        return {
            "success": True,
            "backup_path": backup_path,
            "message": "Backup created successfully"
        }
    except Exception as e:
        logger.error(f"Error creating backup: {e}")
        raise HTTPException(status_code=500, detail="Error creating backup")

@app.get("/api/v1/backup/list")
async def list_backups(version_manager=Depends(get_version_manager)):
    """List available backups"""
    try:
        backups = version_manager.list_backups()
        return {
            "success": True,
            "backups": backups,
            "total": len(backups)
        }
    except Exception as e:
        logger.error(f"Error listing backups: {e}")
        raise HTTPException(status_code=500, detail="Error listing backups")

@app.post("/api/v1/backup/restore")
async def restore_backup(
    backup_name: str,
    version_manager=Depends(get_version_manager)
):
    """Restore from backup"""
    try:
        success = version_manager.restore_backup(backup_name)
        if success:
            return {
                "success": True,
                "message": f"Backup {backup_name} restored successfully"
            }
        else:
            raise HTTPException(status_code=400, detail="Backup restoration failed")
    except Exception as e:
        logger.error(f"Error restoring backup: {e}")
        raise HTTPException(status_code=500, detail="Error restoring backup")

# Upgrade Management Endpoints
@app.get("/api/v1/upgrade/check")
async def check_for_updates(upgrade_manager=Depends(get_upgrade_manager)):
    """Check for available updates"""
    try:
        updates = upgrade_manager.check_for_updates()
        return updates
    except Exception as e:
        logger.error(f"Error checking for updates: {e}")
        raise HTTPException(status_code=500, detail="Error checking for updates")

@app.post("/api/v1/upgrade/perform")
async def perform_upgrade(
    target_version: str = None,
    backup: bool = True,
    upgrade_manager=Depends(get_upgrade_manager)
):
    """Perform application upgrade"""
    try:
        result = upgrade_manager.perform_upgrade(target_version, backup)
        return result
    except Exception as e:
        logger.error(f"Error performing upgrade: {e}")
        raise HTTPException(status_code=500, detail="Error performing upgrade")

@app.post("/api/v1/upgrade/rollback")
async def rollback_upgrade(
    backup_name: str = None,
    upgrade_manager=Depends(get_upgrade_manager)
):
    """Rollback to previous version"""
    try:
        result = upgrade_manager.rollback_upgrade(backup_name)
        return result
    except Exception as e:
        logger.error(f"Error rolling back upgrade: {e}")
        raise HTTPException(status_code=500, detail="Error rolling back upgrade")

# Deployment Tracking Endpoints
@app.post("/api/v1/deployment/record")
async def record_deployment(
    version: str,
    environment: str,
    status: str = "success",
    details: Dict = None,
    deployment_tracker=Depends(get_deployment_tracker)
):
    """Record a deployment"""
    try:
        deployment = deployment_tracker.record_deployment(version, environment, status, details)
        return {
            "success": True,
            "deployment": deployment,
            "message": "Deployment recorded successfully"
        }
    except Exception as e:
        logger.error(f"Error recording deployment: {e}")
        raise HTTPException(status_code=500, detail="Error recording deployment")

@app.get("/api/v1/deployment/history")
async def get_deployment_history(
    limit: int = 10,
    environment: str = None,
    deployment_tracker=Depends(get_deployment_tracker)
):
    """Get deployment history"""
    try:
        deployments = deployment_tracker.get_deployment_history(limit, environment)
        return {
            "success": True,
            "deployments": deployments,
            "total": len(deployments)
        }
    except Exception as e:
        logger.error(f"Error getting deployment history: {e}")
        raise HTTPException(status_code=500, detail="Error getting deployment history")

@app.get("/api/v1/deployment/{deployment_id}")
async def get_deployment_status(
    deployment_id: int,
    deployment_tracker=Depends(get_deployment_tracker)
):
    """Get specific deployment status"""
    try:
        deployment = deployment_tracker.get_deployment_status(deployment_id)
        if deployment:
            return {
                "success": True,
                "deployment": deployment
            }
        else:
            raise HTTPException(status_code=404, detail="Deployment not found")
    except Exception as e:
        logger.error(f"Error getting deployment status: {e}")
        raise HTTPException(status_code=500, detail="Error getting deployment status")

# Docker Version Management Endpoints
@app.get("/api/v1/docker/images")
async def get_docker_images(docker_manager=Depends(get_docker_manager)):
    """Get all Docker images"""
    try:
        images = docker_manager.get_docker_images()
        return {
            "success": True,
            "images": [asdict(image) for image in images],
            "total": len(images)
        }
    except Exception as e:
        logger.error(f"Error getting Docker images: {e}")
        raise HTTPException(status_code=500, detail="Error getting Docker images")

@app.get("/api/v1/docker/containers")
async def get_docker_containers(docker_manager=Depends(get_docker_manager)):
    """Get all containers"""
    try:
        containers = docker_manager.get_containers()
        return {
            "success": True,
            "containers": [asdict(container) for container in containers],
            "total": len(containers)
        }
    except Exception as e:
        logger.error(f"Error getting containers: {e}")
        raise HTTPException(status_code=500, detail="Error getting containers")

@app.post("/api/v1/docker/build")
async def build_docker_image(
    version: str,
    dockerfile: str = "Dockerfile",
    build_context: str = ".",
    docker_manager=Depends(get_docker_manager)
):
    """Build Docker image"""
    try:
        result = docker_manager.build_image(version, dockerfile, build_context)
        return result
    except Exception as e:
        logger.error(f"Error building Docker image: {e}")
        raise HTTPException(status_code=500, detail="Error building Docker image")

@app.post("/api/v1/docker/push")
async def push_docker_image(
    version: str,
    registry: str = None,
    docker_manager=Depends(get_docker_manager)
):
    """Push Docker image to registry"""
    try:
        result = docker_manager.push_image(version, registry)
        return result
    except Exception as e:
        logger.error(f"Error pushing Docker image: {e}")
        raise HTTPException(status_code=500, detail="Error pushing Docker image")

@app.post("/api/v1/docker/pull")
async def pull_docker_image(
    version: str,
    registry: str = None,
    docker_manager=Depends(get_docker_manager)
):
    """Pull Docker image from registry"""
    try:
        result = docker_manager.pull_image(version, registry)
        return result
    except Exception as e:
        logger.error(f"Error pulling Docker image: {e}")
        raise HTTPException(status_code=500, detail="Error pulling Docker image")

@app.post("/api/v1/docker/deploy")
async def deploy_container(
    version: str,
    environment: str = "production",
    config: Dict = None,
    docker_manager=Depends(get_docker_manager)
):
    """Deploy container"""
    try:
        result = docker_manager.deploy_container(version, environment, config)
        return result
    except Exception as e:
        logger.error(f"Error deploying container: {e}")
        raise HTTPException(status_code=500, detail="Error deploying container")

@app.post("/api/v1/docker/rollback")
async def rollback_container(
    target_version: str,
    environment: str = "production",
    docker_manager=Depends(get_docker_manager)
):
    """Rollback container to previous version"""
    try:
        result = docker_manager.rollback_container(target_version, environment)
        return result
    except Exception as e:
        logger.error(f"Error rolling back container: {e}")
        raise HTTPException(status_code=500, detail="Error rolling back container")

@app.post("/api/v1/docker/cleanup")
async def cleanup_old_images(
    keep_versions: int = 5,
    docker_manager=Depends(get_docker_manager)
):
    """Clean up old Docker images"""
    try:
        result = docker_manager.cleanup_old_images(keep_versions)
        return result
    except Exception as e:
        logger.error(f"Error cleaning up old images: {e}")
        raise HTTPException(status_code=500, detail="Error cleaning up old images")

@app.get("/api/v1/docker/history/{image_name}")
async def get_image_history(
    image_name: str,
    docker_manager=Depends(get_docker_manager)
):
    """Get build history for an image"""
    try:
        history = docker_manager.get_image_history(image_name)
        return {
            "success": True,
            "history": history,
            "total": len(history)
        }
    except Exception as e:
        logger.error(f"Error getting image history: {e}")
        raise HTTPException(status_code=500, detail="Error getting image history")

# Docker Orchestration Endpoints
@app.post("/api/v1/docker/orchestrate/blue-green")
async def blue_green_deployment(
    new_version: str,
    environment: str = "production",
    docker_orchestrator=Depends(get_docker_orchestrator)
):
    """Perform blue-green deployment"""
    try:
        result = docker_orchestrator.blue_green_deployment(new_version, environment)
        return result
    except Exception as e:
        logger.error(f"Error performing blue-green deployment: {e}")
        raise HTTPException(status_code=500, detail="Error performing blue-green deployment")

@app.post("/api/v1/docker/orchestrate/rolling")
async def rolling_update(
    new_version: str,
    environment: str = "production",
    max_unavailable: int = 1,
    docker_orchestrator=Depends(get_docker_orchestrator)
):
    """Perform rolling update"""
    try:
        result = docker_orchestrator.rolling_update(new_version, environment, max_unavailable)
        return result
    except Exception as e:
        logger.error(f"Error performing rolling update: {e}")
        raise HTTPException(status_code=500, detail="Error performing rolling update")

@app.post("/api/v1/logs/parse", response_model=Dict)
async def parse_log_entry(log_entry: LogEntry, parser=Depends(get_ssh_parser)):
    """Parse a single SSH log entry"""
    try:
        parsed_log = parser.parse(log_entry.raw_log)
        
        if not parsed_log:
            raise HTTPException(status_code=400, detail="Failed to parse log entry")
        
        return {
            "success": True,
            "parsed_log": {
                "timestamp": parsed_log.timestamp.isoformat(),
                "source": parsed_log.source,
                "event_type": parsed_log.event_type,
                "username": parsed_log.username,
                "ip_address": parsed_log.ip_address,
                "port": parsed_log.port,
                "details": parsed_log.details
            }
        }
    except Exception as e:
        logger.error(f"Error parsing log entry: {e}")
        raise HTTPException(status_code=500, detail="Error parsing log entry")

@app.post("/api/v1/logs/batch", response_model=Dict)
async def parse_batch_logs(batch: BatchLogEntry, parser=Depends(get_ssh_parser)):
    """Parse multiple SSH log entries"""
    try:
        parsed_logs = parser.parse_batch(batch.logs)
        
        return {
            "success": True,
            "total_logs": len(batch.logs),
            "parsed_logs": len(parsed_logs),
            "logs": [
                {
                    "timestamp": log.timestamp.isoformat(),
                    "source": log.source,
                    "event_type": log.event_type,
                    "username": log.username,
                    "ip_address": log.ip_address,
                    "port": log.port,
                    "details": log.details
                }
                for log in parsed_logs
            ]
        }
    except Exception as e:
        logger.error(f"Error parsing batch logs: {e}")
        raise HTTPException(status_code=500, detail="Error parsing batch logs")

@app.post("/api/v1/logs/ingest", response_model=Dict)
async def ingest_log_entry(log_entry: LogEntry, 
                          parser=Depends(get_ssh_parser),
                          db=Depends(get_db_connection)):
    """Ingest and store a single log entry"""
    try:
        # Parse the log entry
        parsed_log = parser.parse(log_entry.raw_log)
        
        if not parsed_log:
            raise HTTPException(status_code=400, detail="Failed to parse log entry")
        
        # Store in database
        log_id = db.insert_log_entry(parsed_log)
        
        if not log_id:
            raise HTTPException(status_code=500, detail="Failed to store log entry")
        
        return {
            "success": True,
            "log_id": log_id,
            "message": "Log entry ingested successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error ingesting log entry: {e}")
        raise HTTPException(status_code=500, detail="Error ingesting log entry")

@app.post("/api/v1/logs/ingest/batch", response_model=Dict)
async def ingest_batch_logs(batch: BatchLogEntry,
                          parser=Depends(get_ssh_parser),
                          db=Depends(get_db_connection)):
    """Ingest and store multiple log entries"""
    try:
        # Parse the log entries
        parsed_logs = parser.parse_batch(batch.logs)
        
        if not parsed_logs:
            raise HTTPException(status_code=400, detail="No valid log entries parsed")
        
        # Store in database
        inserted_count = db.insert_log_batch(parsed_logs)
        
        return {
            "success": True,
            "total_logs": len(batch.logs),
            "parsed_logs": len(parsed_logs),
            "inserted_logs": inserted_count,
            "message": f"Successfully ingested {inserted_count} log entries"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error ingesting batch logs: {e}")
        raise HTTPException(status_code=500, detail="Error ingesting batch logs")

@app.get("/api/v1/logs/recent", response_model=List[Dict])
async def get_recent_logs(hours: int = 24, limit: int = 1000, db=Depends(get_db_connection)):
    """Get recent security logs"""
    try:
        logs = db.get_recent_logs(hours=hours, limit=limit)
        
        return [
            {
                "id": str(log["id"]),
                "timestamp": log["timestamp"].isoformat(),
                "source": log["source"],
                "event_type": log["event_type"],
                "username": log["username"],
                "ip_address": str(log["ip_address"]) if log["ip_address"] else None,
                "port": log["port"],
                "details": log["details"]
            }
            for log in logs
        ]
    except Exception as e:
        logger.error(f"Error getting recent logs: {e}")
        raise HTTPException(status_code=500, detail="Error getting recent logs")

@app.get("/api/v1/threats/detect", response_model=List[Dict])
async def detect_threats(hours: int = 1, pipeline=Depends(get_threat_pipeline)):
    """Detect threats in recent logs"""
    try:
        if not pipeline.anomaly_detector.is_trained:
            raise HTTPException(status_code=400, detail="ML model not trained")
        
        threats = pipeline.detect_threats(hours_back=hours)
        
        return [
            {
                "alert_id": threat.get("alert_id"),
                "timestamp": threat["timestamp"].isoformat(),
                "threat_type": threat["threat_type"],
                "severity": threat["severity"],
                "confidence_score": threat["confidence_score"],
                "description": threat["description"]
            }
            for threat in threats
        ]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error detecting threats: {e}")
        raise HTTPException(status_code=500, detail="Error detecting threats")

@app.post("/api/v1/ml/train", response_model=Dict)
async def train_model(training_request: TrainingRequest, 
                    background_tasks: BackgroundTasks,
                    pipeline=Depends(get_threat_pipeline)):
    """Train the ML anomaly detection model"""
    try:
        # Start training in background
        background_tasks.add_task(train_model_background, training_request.days_back, pipeline)
        
        return {
            "success": True,
            "message": f"Model training started with {training_request.days_back} days of data",
            "status": "training_in_progress"
        }
    except Exception as e:
        logger.error(f"Error starting model training: {e}")
        raise HTTPException(status_code=500, detail="Error starting model training")

@app.post("/api/v1/ml/train-sync", response_model=Dict)
async def train_model_sync(training_request: TrainingRequest, 
                         pipeline=Depends(get_threat_pipeline)):
    """Train the ML anomaly detection model synchronously"""
    try:
        logger.info(f"Starting synchronous model training with {training_request.days_back} days of data")
        success = pipeline.train_model(days_back=training_request.days_back)
        
        if success:
            return {
                "success": True,
                "message": f"Model trained successfully with {training_request.days_back} days of data",
                "status": "training_completed"
            }
        else:
            return {
                "success": False,
                "message": "Model training failed",
                "status": "training_failed"
            }
    except Exception as e:
        logger.error(f"Error in synchronous model training: {e}")
        raise HTTPException(status_code=500, detail="Error in model training")

@app.get("/api/v1/ml/status", response_model=Dict)
async def get_model_status(pipeline=Depends(get_threat_pipeline)):
    """Get ML model status"""
    try:
        return {
            "model_trained": pipeline.anomaly_detector.is_trained,
            "model_path": pipeline.anomaly_detector.model_path,
            "contamination": pipeline.anomaly_detector.contamination,
            "n_estimators": pipeline.anomaly_detector.n_estimators
        }
    except Exception as e:
        logger.error(f"Error getting model status: {e}")
        raise HTTPException(status_code=500, detail="Error getting model status")

@app.get("/api/v1/ml/performance", response_model=Dict)
async def get_model_performance(pipeline=Depends(get_threat_pipeline)):
    """Get ML model performance metrics"""
    try:
        performance = pipeline.anomaly_detector.evaluate_model_performance()
        
        if "error" in performance:
            raise HTTPException(status_code=400, detail=performance["error"])
        
        return performance
    except Exception as e:
        logger.error(f"Error getting model performance: {e}")
        raise HTTPException(status_code=500, detail="Error getting model performance")

@app.get("/api/v1/threats/alerts", response_model=List[Dict])
async def get_threat_alerts(hours: int = 24, db=Depends(get_db_connection)):
    """Get recent threat alerts"""
    try:
        # This would need to be implemented in the database connection
        # For now, return empty list
        return []
    except Exception as e:
        logger.error(f"Error getting threat alerts: {e}")
        raise HTTPException(status_code=500, detail="Error getting threat alerts")

@app.get("/api/v1/stats/summary", response_model=Dict)
async def get_statistics_summary(db=Depends(get_db_connection)):
    """Get statistics summary"""
    try:
        # Get daily statistics
        stats = db.get_daily_statistics()
        
        # Get failed logins by IP
        failed_logins = db.get_failed_logins_by_ip(hours=1)
        
        return {
            "daily_stats": stats,
            "recent_failed_logins": failed_logins[:10],  # Top 10
            "total_failed_ips": len(failed_logins)
        }
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail="Error getting statistics")

@app.get("/api/v1/system/status", response_model=SystemStatus)
async def get_system_status(pipeline=Depends(get_threat_pipeline), db=Depends(get_db_connection)):
    """Get comprehensive system status"""
    try:
        # Get recent threats count
        threats = pipeline.detect_threats(hours=1) if pipeline.anomaly_detector.is_trained else []
        
        # Get total logs count (this would need to be implemented)
        total_logs = 0  # Placeholder
        
        return SystemStatus(
            status="healthy",
            timestamp=datetime.utcnow(),
            model_trained=pipeline.anomaly_detector.is_trained,
            database_connected=db.test_connection(),
            total_logs=total_logs,
            recent_threats=len(threats)
        )
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail="Error getting system status")

# Background task for model training
async def train_model_background(days_back: int, pipeline: ThreatDetectionPipeline):
    """Background task for model training"""
    try:
        logger.info(f"Starting model training with {days_back} days of data")
        success = pipeline.train_model(days_back=days_back)
        
        if success:
            logger.info("Model training completed successfully")
        else:
            logger.error("Model training failed")
            
    except Exception as e:
        logger.error(f"Error in background model training: {e}")

# Run the application
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
