"""
Docker Version Management System for Cloud Log Threat Detection Framework
"""

import os
import json
import subprocess
import docker
import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class DockerImageInfo:
    """Docker image information"""
    name: str
    tag: str
    image_id: str
    size: str
    created: datetime.datetime
    digest: Optional[str] = None
    app_version: str = "1.0.0"
    build_date: Optional[datetime.datetime] = None
    git_commit: Optional[str] = None


@dataclass
class ContainerInfo:
    """Container information"""
    name: str
    container_id: str
    image: str
    status: str
    created: datetime.datetime
    ports: List[str]
    environment: Dict[str, str]


class DockerVersionManager:
    """Manages Docker image and container versions"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.docker_images_file = self.config_dir / "docker_images.json"
        self.containers_file = self.config_dir / "containers.json"
        self.docker_registry = os.getenv("DOCKER_REGISTRY", "localhost:5000")
        self.app_name = os.getenv("APP_NAME", "threat-detection")
        
        # Initialize Docker client
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            print(f"Error initializing Docker client: {e}")
            self.docker_client = None
        
        # Ensure config directory exists
        self.config_dir.mkdir(exist_ok=True)
        
        # Load existing data
        self.docker_images = self._load_docker_images()
        self.containers = self._load_containers()
    
    def _load_docker_images(self) -> List[DockerImageInfo]:
        """Load Docker image information"""
        if self.docker_images_file.exists():
            with open(self.docker_images_file, 'r') as f:
                data = json.load(f)
                images = []
                for item in data:
                    item['created'] = datetime.datetime.fromisoformat(item['created'])
                    if item.get('build_date'):
                        item['build_date'] = datetime.datetime.fromisoformat(item['build_date'])
                    images.append(DockerImageInfo(**item))
                return images
        return []
    
    def _load_containers(self) -> List[ContainerInfo]:
        """Load container information"""
        if self.containers_file.exists():
            with open(self.containers_file, 'r') as f:
                data = json.load(f)
                containers = []
                for item in data:
                    item['created'] = datetime.datetime.fromisoformat(item['created'])
                    containers.append(ContainerInfo(**item))
                return containers
        return []
    
    def _save_docker_images(self):
        """Save Docker image information"""
        data = []
        for image in self.docker_images:
            item = asdict(image)
            item['created'] = image.created.isoformat()
            if image.build_date:
                item['build_date'] = image.build_date.isoformat()
            data.append(item)
        
        with open(self.docker_images_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _save_containers(self):
        """Save container information"""
        data = []
        for container in self.containers:
            item = asdict(container)
            item['created'] = container.created.isoformat()
            data.append(item)
        
        with open(self.containers_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_docker_images(self) -> List[DockerImageInfo]:
        """Get all Docker images"""
        if not self.docker_client:
            return []
        
        try:
            images = []
            for image in self.docker_client.images.list():
                if self.app_name in image.tags[0] if image.tags else False:
                    # Extract image information
                    tag = image.tags[0] if image.tags else "latest"
                    image_info = DockerImageInfo(
                        name=image.tags[0].split(':')[0] if image.tags else "unknown",
                        tag=tag.split(':')[1] if ':' in tag else "latest",
                        image_id=image.id,
                        size=self._format_size(image.attrs['Size']),
                        created=datetime.datetime.fromtimestamp(image.attrs['Created']),
                        digest=image.attrs.get('RepoDigests', [None])[0]
                    )
                    images.append(image_info)
            
            self.docker_images = images
            self._save_docker_images()
            return images
            
        except Exception as e:
            print(f"Error getting Docker images: {e}")
            return self.docker_images
    
    def get_containers(self) -> List[ContainerInfo]:
        """Get all containers"""
        if not self.docker_client:
            return []
        
        try:
            containers = []
            for container in self.docker_client.containers.list(all=True):
                if self.app_name in container.name:
                    # Extract container information
                    container_info = ContainerInfo(
                        name=container.name,
                        container_id=container.id,
                        image=container.image.tags[0] if container.image.tags else "unknown",
                        status=container.status,
                        created=datetime.datetime.fromtimestamp(container.attrs['Created']),
                        ports=[f"{p['HostPort']}:{p['PrivatePort']}" for p in container.ports.values() if p],
                        environment={k: v for k, v in container.attrs['Config']['Env'].items() if '=' in k}
                    )
                    containers.append(container_info)
            
            self.containers = containers
            self._save_containers()
            return containers
            
        except Exception as e:
            print(f"Error getting containers: {e}")
            return self.containers
    
    def _format_size(self, size_bytes: int) -> str:
        """Format size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
    
    def build_image(self, version: str, dockerfile: str = "Dockerfile", 
                   build_context: str = ".", git_commit: str = None) -> Dict:
        """
        Build Docker image with version tag
        
        Args:
            version: Version tag for the image
            dockerfile: Dockerfile path
            build_context: Build context directory
            git_commit: Git commit hash
            
        Returns:
            Build result
        """
        try:
            image_name = f"{self.app_name}:{version}"
            
            # Build labels
            labels = {
                "app.version": version,
                "build.date": datetime.datetime.now().isoformat(),
                "app.name": self.app_name
            }
            
            if git_commit:
                labels["git.commit"] = git_commit
            
            # Build image
            image, build_logs = self.docker_client.images.build(
                path=build_context,
                dockerfile=dockerfile,
                tag=image_name,
                labels=labels
            )
            
            # Record image information
            image_info = DockerImageInfo(
                name=self.app_name,
                tag=version,
                image_id=image.id,
                size=self._format_size(image.attrs['Size']),
                created=datetime.datetime.fromtimestamp(image.attrs['Created']),
                app_version=version,
                build_date=datetime.datetime.now(),
                git_commit=git_commit
            )
            
            self.docker_images.append(image_info)
            self._save_docker_images()
            
            return {
                "success": True,
                "image_name": image_name,
                "image_id": image.id,
                "size": image_info.size,
                "build_logs": [log.get('stream', '') for log in build_logs]
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def push_image(self, version: str, registry: str = None) -> Dict:
        """
        Push Docker image to registry
        
        Args:
            version: Version tag to push
            registry: Registry URL (optional)
            
        Returns:
            Push result
        """
        try:
            registry = registry or self.docker_registry
            image_name = f"{self.app_name}:{version}"
            remote_image = f"{registry}/{image_name}"
            
            # Tag image for registry
            image = self.docker_client.images.get(image_name)
            image.tag(remote_image, version)
            
            # Push image
            push_logs = self.docker_client.images.push(remote_image, version)
            
            return {
                "success": True,
                "image_name": remote_image,
                "push_logs": push_logs
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def pull_image(self, version: str, registry: str = None) -> Dict:
        """
        Pull Docker image from registry
        
        Args:
            version: Version tag to pull
            registry: Registry URL (optional)
            
        Returns:
            Pull result
        """
        try:
            registry = registry or self.docker_registry
            image_name = f"{registry}/{self.app_name}:{version}"
            
            # Pull image
            pull_logs = self.docker_client.images.pull(image_name)
            
            return {
                "success": True,
                "image_name": image_name,
                "pull_logs": pull_logs
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def deploy_container(self, version: str, environment: str = "production", 
                        config: Dict = None) -> Dict:
        """
        Deploy container with specific version
        
        Args:
            version: Image version to deploy
            environment: Environment name
            config: Container configuration
            
        Returns:
            Deployment result
        """
        try:
            image_name = f"{self.app_name}:{version}"
            container_name = f"{self.app_name}-{environment}"
            
            # Default configuration
            default_config = {
                "detach": True,
                "name": container_name,
                "ports": {"8000/tcp": 8000},
                "environment": {
                    "ENVIRONMENT": environment,
                    "APP_VERSION": version
                },
                "restart_policy": {"Name": "unless-stopped"}
            }
            
            # Merge with provided config
            if config:
                default_config.update(config)
            
            # Stop and remove existing container if exists
            try:
                existing_container = self.docker_client.containers.get(container_name)
                existing_container.stop()
                existing_container.remove()
            except docker.errors.NotFound:
                pass
            
            # Deploy new container
            container = self.docker_client.containers.run(
                image_name,
                **default_config
            )
            
            # Record container information
            container_info = ContainerInfo(
                name=container_name,
                container_id=container.id,
                image=image_name,
                status="running",
                created=datetime.datetime.now(),
                ports=[f"{default_config['ports']['8000/tcp']}:8000"],
                environment=default_config["environment"]
            )
            
            self.containers.append(container_info)
            self._save_containers()
            
            return {
                "success": True,
                "container_id": container.id,
                "container_name": container_name,
                "image": image_name,
                "status": "running"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def rollback_container(self, target_version: str, environment: str = "production") -> Dict:
        """
        Rollback container to previous version
        
        Args:
            target_version: Target version to rollback to
            environment: Environment name
            
        Returns:
            Rollback result
        """
        try:
            # Deploy target version
            result = self.deploy_container(target_version, environment)
            
            if result["success"]:
                result["message"] = f"Successfully rolled back to version {target_version}"
            
            return result
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def cleanup_old_images(self, keep_versions: int = 5) -> Dict:
        """
        Clean up old Docker images
        
        Args:
            keep_versions: Number of versions to keep
            
        Returns:
            Cleanup result
        """
        try:
            # Get images sorted by creation date
            images = sorted(self.docker_images, key=lambda x: x.created, reverse=True)
            
            # Keep only the latest versions
            images_to_remove = images[keep_versions:]
            
            removed_images = []
            for image in images_to_remove:
                try:
                    docker_image = self.docker_client.images.get(f"{image.name}:{image.tag}")
                    self.docker_client.images.remove(docker_image.id, force=True)
                    removed_images.append(f"{image.name}:{image.tag}")
                except docker.errors.ImageNotFound:
                    pass
            
            # Update image list
            self.docker_images = images[:keep_versions]
            self._save_docker_images()
            
            return {
                "success": True,
                "removed_images": removed_images,
                "total_removed": len(removed_images)
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_image_history(self, image_name: str) -> List[Dict]:
        """Get build history for an image"""
        try:
            image = self.docker_client.images.get(image_name)
            history = image.history()
            
            return [
                {
                    "id": h["Id"],
                    "created": datetime.datetime.fromtimestamp(h["Created"]).isoformat(),
                    "created_by": h["CreatedBy"],
                    "size": h["Size"],
                    "comment": h["Comment"]
                }
                for h in history
            ]
            
        except Exception as e:
            return []


class DockerOrchestrator:
    """Orchestrates Docker deployments with zero-downtime"""
    
    def __init__(self, docker_manager: DockerVersionManager):
        self.docker_manager = docker_manager
        self.load_balancer_config = {
            "nginx": {
                "template": "config/nginx.conf.template",
                "output": "config/nginx.conf"
            }
        }
    
    def blue_green_deployment(self, new_version: str, environment: str = "production") -> Dict:
        """
        Perform blue-green deployment
        
        Args:
            new_version: New version to deploy
            environment: Environment name
            
        Returns:
            Deployment result
        """
        try:
            blue_container = f"{self.docker_manager.app_name}-{environment}-blue"
            green_container = f"{self.docker_manager.app_name}-{environment}-green"
            
            # Determine current active container
            current_active = self._get_active_container(blue_container, green_container)
            target_container = green_container if current_active == blue_container else blue_container
            
            # Deploy new version to target container
            deploy_config = {
                "name": target_container,
                "ports": {"8000/tcp": 8001 if target_container.endswith("green") else 8002}
            }
            
            result = self.docker_manager.deploy_container(new_version, environment, deploy_config)
            
            if result["success"]:
                # Health check
                if self._health_check(target_container):
                    # Switch traffic to new container
                    self._switch_traffic(target_container)
                    
                    # Stop old container
                    try:
                        old_container = self.docker_manager.docker_client.containers.get(current_active)
                        old_container.stop()
                    except docker.errors.NotFound:
                        pass
                    
                    return {
                        "success": True,
                        "deployment_type": "blue-green",
                        "new_container": target_container,
                        "old_container": current_active,
                        "traffic_switched": True
                    }
                else:
                    # Rollback on health check failure
                    try:
                        failed_container = self.docker_manager.docker_client.containers.get(target_container)
                        failed_container.stop()
                    except docker.errors.NotFound:
                        pass
                    
                    return {
                        "success": False,
                        "error": "Health check failed, deployment rolled back"
                    }
            
            return result
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _get_active_container(self, blue_container: str, green_container: str) -> str:
        """Get currently active container"""
        try:
            blue = self.docker_manager.docker_client.containers.get(blue_container)
            if blue.status == "running":
                return blue_container
        except docker.errors.NotFound:
            pass
        
        try:
            green = self.docker_manager.docker_client.containers.get(green_container)
            if green.status == "running":
                return green_container
        except docker.errors.NotFound:
            pass
        
        return blue_container  # Default to blue
    
    def _health_check(self, container_name: str) -> bool:
        """Perform health check on container"""
        try:
            container = self.docker_manager.docker_client.containers.get(container_name)
            
            # Check if container is running
            if container.status != "running":
                return False
            
            # Check HTTP health endpoint
            import requests
            
            # Get container port
            port = container.ports.get('8000/tcp', [{}])[0].get('HostPort', 8000)
            
            # Health check
            response = requests.get(f"http://localhost:{port}/health", timeout=10)
            return response.status_code == 200
            
        except Exception:
            return False
    
    def _switch_traffic(self, target_container: str):
        """Switch traffic to target container"""
        # This would update load balancer configuration
        # For now, just log the switch
        print(f"Traffic switched to {target_container}")
    
    def rolling_update(self, new_version: str, environment: str = "production", 
                      max_unavailable: int = 1) -> Dict:
        """
        Perform rolling update
        
        Args:
            new_version: New version to deploy
            environment: Environment name
            max_unavailable: Maximum unavailable containers
            
        Returns:
            Update result
        """
        try:
            # This is a simplified rolling update
            # In production, you'd have multiple container instances
            
            result = self.docker_manager.deploy_container(new_version, environment)
            
            return {
                "success": result["success"],
                "deployment_type": "rolling",
                "updated_containers": 1,
                "max_unavailable": max_unavailable
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
