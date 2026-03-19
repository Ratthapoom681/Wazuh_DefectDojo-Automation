import os
import yaml
from pydantic import BaseModel
from typing import List, Dict

class RoutingRule(BaseModel):
    match_rule_groups: List[str]
    owner_group: str

class TagRule(BaseModel):
    match_rule_groups: List[str]
    tags: List[str]

class TeamConfig(BaseModel):
    users: List[str]
    fallback_user: str

class AppConfig(BaseModel):
    teams: Dict[str, TeamConfig]
    routing_rules: List[RoutingRule]
    tag_rules: List[TagRule] = []
    default_owner_group: str

def load_config(path: str = "config.yaml") -> AppConfig:
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return AppConfig(**data)

DOJO_URL = os.getenv("DEFECTDOJO_URL", "http://localhost:8080").rstrip('/')
DOJO_API_KEY = os.getenv("DEFECTDOJO_API_KEY", "")
DB_PATH = os.getenv("ASSIGNMENT_DB_PATH", "assignments.sqlite")
