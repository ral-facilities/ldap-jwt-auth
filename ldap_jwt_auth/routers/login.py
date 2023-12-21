"""
Module for providing an API router which defines login route(s).
"""
import logging

from fastapi import APIRouter

logger = logging.getLogger()

router = APIRouter(prefix="/login", tags=["authentication"])
