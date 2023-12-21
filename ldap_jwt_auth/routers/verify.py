"""
Module for providing an API router which defines a route for managing verification of JWT tokens.
"""
import logging

from fastapi import APIRouter

logger = logging.getLogger()

router = APIRouter(prefix="/verify", tags=["authentication"])
