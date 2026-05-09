"""
Core configuration settings for the Cloud Log Threat Detection Framework
"""

import os
from typing import List

class Settings:
    """Application configuration settings"""
    
    # Application settings
    APP_NAME: str = "Cloud Log Threat Detection Framework"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    # Database settings
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:password@localhost:5432/threat_detection"
    )
    
    # ML Model settings
    MODEL_PATH: str = os.getenv("MODEL_PATH", "models/anomaly_detector.pkl")
    CONTAMINATION: float = float(os.getenv("CONTAMINATION", "0.1"))
    N_ESTIMATORS: int = int(os.getenv("N_ESTIMATORS", "100"))
    
    # API settings
    API_PREFIX: str = "/api/v1"
    CORS_ORIGINS: List[str] = ["*"]
    
    # Security settings
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-here")
    
    # Logging settings
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Performance settings
    MAX_BATCH_SIZE: int = int(os.getenv("MAX_BATCH_SIZE", "1000"))
    QUERY_TIMEOUT: int = int(os.getenv("QUERY_TIMEOUT", "30"))
    
    # Version management settings
    CONFIG_DIR: str = os.getenv("CONFIG_DIR", "config")
    BACKUP_DIR: str = os.getenv("BACKUP_DIR", "backups")
    
    @property
    def database_config(self) -> dict:
        """Get database configuration"""
        return {
            "host": os.getenv("DB_HOST", "localhost"),
            "port": int(os.getenv("DB_PORT", "5432")),
            "database": os.getenv("DB_NAME", "threat_detection"),
            "user": os.getenv("DB_USER", "postgres"),
            "password": os.getenv("DB_PASSWORD", "password")
        }

# Create global settings instance
settings = Settings()
