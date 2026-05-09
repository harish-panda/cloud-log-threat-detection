"""
Version Management and Upgrade System for Cloud Log Threat Detection Framework
"""

import os
import json
import hashlib
import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import subprocess
import shutil


@dataclass
class VersionInfo:
    """Version information data class"""
    version: str
    build_number: int
    release_date: datetime.datetime
    git_commit: Optional[str] = None
    app_version: str = "1.0.0"
    ml_model_version: str = "1.0.0"
    database_schema_version: str = "1.0.0"
    api_version: str = "v1"
    changes: List[str] = None
    is_stable: bool = True
    
    def __post_init__(self):
        if self.changes is None:
            self.changes = []


class VersionManager:
    """Manages application versioning and upgrades"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.versions_file = self.config_dir / "versions.json"
        self.current_version_file = self.config_dir / "current_version.json"
        self.backup_dir = Path("backups")
        
        # Ensure directories exist
        self.config_dir.mkdir(exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)
        
        # Load current version
        self.current_version = self._load_current_version()
        
    def _load_current_version(self) -> VersionInfo:
        """Load current version information"""
        if self.current_version_file.exists():
            with open(self.current_version_file, 'r') as f:
                data = json.load(f)
                data['release_date'] = datetime.datetime.fromisoformat(data['release_date'])
                return VersionInfo(**data)
        else:
            # Create initial version
            return self._create_initial_version()
    
    def _create_initial_version(self) -> VersionInfo:
        """Create initial version information"""
        version = VersionInfo(
            version="1.0.0",
            build_number=1,
            release_date=datetime.datetime.now(),
            git_commit=self._get_git_commit(),
            app_version="1.0.0",
            ml_model_version="1.0.0",
            database_schema_version="1.0.0",
            api_version="v1",
            changes=["Initial release", "Basic threat detection", "ML model training", "Grafana dashboards"],
            is_stable=True
        )
        self._save_current_version(version)
        return version
    
    def _get_git_commit(self) -> Optional[str]:
        """Get current git commit hash"""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                cwd=os.getcwd()
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    def _save_current_version(self, version: VersionInfo):
        """Save current version information"""
        data = asdict(version)
        data['release_date'] = version.release_date.isoformat()
        
        with open(self.current_version_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        self.current_version = version
    
    def get_version_info(self) -> Dict:
        """Get current version information"""
        return asdict(self.current_version)
    
    def increment_version(self, version_type: str = "patch", changes: List[str] = None) -> VersionInfo:
        """
        Increment version number
        
        Args:
            version_type: 'major', 'minor', or 'patch'
            changes: List of changes for this version
            
        Returns:
            New version information
        """
        version_parts = self.current_version.version.split('.')
        major, minor, patch = int(version_parts[0]), int(version_parts[1]), int(version_parts[2])
        
        if version_type == "major":
            major += 1
            minor = 0
            patch = 0
        elif version_type == "minor":
            minor += 1
            patch = 0
        else:  # patch
            patch += 1
        
        new_version = f"{major}.{minor}.{patch}"
        
        new_version_info = VersionInfo(
            version=new_version,
            build_number=self.current_version.build_number + 1,
            release_date=datetime.datetime.now(),
            git_commit=self._get_git_commit(),
            app_version=new_version,
            ml_model_version=new_version,
            database_schema_version=new_version,
            api_version="v1",
            changes=changes or [],
            is_stable=True
        )
        
        self._save_current_version(new_version_info)
        return new_version_info
    
    def create_backup(self, backup_name: str = None) -> str:
        """
        Create backup of current application state
        
        Args:
            backup_name: Optional backup name
            
        Returns:
            Backup file path
        """
        if backup_name is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"backup_v{self.current_version.version}_{timestamp}"
        
        backup_path = self.backup_dir / f"{backup_name}.tar.gz"
        
        # Create backup of important files
        import tarfile
        
        with tarfile.open(backup_path, "w:gz") as tar:
            # Backup application code
            tar.add("src", arcname="src")
            
            # Backup configuration
            tar.add("config", arcname="config")
            
            # Backup models
            if os.path.exists("models"):
                tar.add("models", arcname="models")
            
            # Backup documentation
            tar.add("docs", arcname="docs")
            
            # Backup database schema
            tar.add("database", arcname="database")
            
            # Backup monitoring configuration
            if os.path.exists("monitoring"):
                tar.add("monitoring/grafana/provisioning", arcname="monitoring/grafana/provisioning")
        
        return str(backup_path)
    
    def list_backups(self) -> List[Dict]:
        """List all available backups"""
        backups = []
        
        for backup_file in self.backup_dir.glob("*.tar.gz"):
            stat = backup_file.stat()
            backups.append({
                "name": backup_file.stem,
                "path": str(backup_file),
                "size": stat.st_size,
                "created": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
        
        return sorted(backups, key=lambda x: x['created'], reverse=True)
    
    def restore_backup(self, backup_name: str) -> bool:
        """
        Restore from backup
        
        Args:
            backup_name: Backup file name (without extension)
            
        Returns:
            True if restore successful
        """
        backup_path = self.backup_dir / f"{backup_name}.tar.gz"
        
        if not backup_path.exists():
            return False
        
        try:
            import tarfile
            
            with tarfile.open(backup_path, "r:gz") as tar:
                tar.extractall()
            
            # Restart services to apply restored configuration
            self._restart_services()
            
            return True
            
        except Exception as e:
            print(f"Error restoring backup: {e}")
            return False
    
    def _restart_services(self):
        """Restart application services"""
        try:
            subprocess.run(["docker-compose", "restart"], check=True, capture_output=True)
        except Exception:
            pass


class UpgradeManager:
    """Manages application upgrades"""
    
    def __init__(self, version_manager: VersionManager):
        self.version_manager = version_manager
        self.upgrade_scripts_dir = Path("scripts/upgrades")
        self.upgrade_scripts_dir.mkdir(parents=True, exist_ok=True)
    
    def check_for_updates(self) -> Dict:
        """Check for available updates"""
        current_version = self.version_manager.current_version
        
        # In a real implementation, this would check against a repository
        # For now, simulate update checking
        return {
            "current_version": current_version.version,
            "latest_version": "1.1.0",  # Simulated
            "updates_available": True,
            "update_description": "Performance improvements and bug fixes",
            "update_size": "25.3 MB",
            "update_type": "minor"
        }
    
    def perform_upgrade(self, target_version: str = None, backup: bool = True) -> Dict:
        """
        Perform application upgrade
        
        Args:
            target_version: Target version to upgrade to
            backup: Whether to create backup before upgrade
            
        Returns:
            Upgrade result
        """
        try:
            # Create backup if requested
            backup_path = None
            if backup:
                backup_path = self.version_manager.create_backup("pre_upgrade_backup")
            
            # Simulate upgrade process
            upgrade_steps = [
                "Stopping services",
                "Backing up data",
                "Downloading updates",
                "Installing new version",
                "Migrating database",
                "Updating configuration",
                "Restarting services",
                "Verifying upgrade"
            ]
            
            # Execute upgrade steps
            for i, step in enumerate(upgrade_steps):
                print(f"Step {i+1}/{len(upgrade_steps)}: {step}")
                # Simulate step execution
                import time
                time.sleep(0.5)
            
            # Update version
            new_version = self.version_manager.increment_version(
                version_type="minor",
                changes=["Performance improvements", "Bug fixes", "Enhanced ML algorithms"]
            )
            
            return {
                "success": True,
                "new_version": new_version.version,
                "backup_path": backup_path,
                "upgrade_steps": upgrade_steps,
                "message": "Upgrade completed successfully"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "Upgrade failed"
            }
    
    def rollback_upgrade(self, backup_name: str = None) -> Dict:
        """
        Rollback to previous version
        
        Args:
            backup_name: Backup to restore from (optional)
            
        Returns:
            Rollback result
        """
        try:
            if backup_name is None:
                # Get most recent backup
                backups = self.version_manager.list_backups()
                if not backups:
                    return {"success": False, "error": "No backups available"}
                backup_name = backups[0]["name"]
            
            # Restore from backup
            success = self.version_manager.restore_backup(backup_name)
            
            if success:
                return {
                    "success": True,
                    "restored_from": backup_name,
                    "message": "Rollback completed successfully"
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to restore backup"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "Rollback failed"
            }


class DeploymentTracker:
    """Tracks deployment history and status"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.deployments_file = self.config_dir / "deployments.json"
        
        # Load deployment history
        self.deployments = self._load_deployments()
    
    def _load_deployments(self) -> List[Dict]:
        """Load deployment history"""
        if self.deployments_file.exists():
            with open(self.deployments_file, 'r') as f:
                return json.load(f)
        else:
            return []
    
    def _save_deployments(self):
        """Save deployment history"""
        with open(self.deployments_file, 'w') as f:
            json.dump(self.deployments, f, indent=2, default=str)
    
    def record_deployment(self, version: str, environment: str, status: str = "success", 
                         details: Dict = None) -> Dict:
        """
        Record a deployment
        
        Args:
            version: Version deployed
            environment: Environment (dev/staging/prod)
            status: Deployment status
            details: Additional deployment details
            
        Returns:
            Deployment record
        """
        deployment = {
            "id": len(self.deployments) + 1,
            "version": version,
            "environment": environment,
            "status": status,
            "timestamp": datetime.datetime.now().isoformat(),
            "deployed_by": "system",  # Could be user ID
            "details": details or {},
            "duration": 0,  # Deployment duration in seconds
            "rollback_available": True
        }
        
        self.deployments.append(deployment)
        self._save_deployments()
        
        return deployment
    
    def get_deployment_history(self, limit: int = 10, environment: str = None) -> List[Dict]:
        """
        Get deployment history
        
        Args:
            limit: Maximum number of deployments to return
            environment: Filter by environment (optional)
            
        Returns:
            List of deployments
        """
        deployments = self.deployments
        
        if environment:
            deployments = [d for d in deployments if d["environment"] == environment]
        
        # Sort by timestamp (most recent first) and limit
        deployments.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return deployments[:limit]
    
    def get_deployment_status(self, deployment_id: int) -> Optional[Dict]:
        """Get status of specific deployment"""
        for deployment in self.deployments:
            if deployment["id"] == deployment_id:
                return deployment
        return None
