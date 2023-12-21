"""
Module for providing an API router which defines a route for managing the refreshing/updating of a JWT access token
using a JWT refresh token.
"""
import logging

from fastapi import APIRouter

logger = logging.getLogger()

router = APIRouter(prefix="/refresh", tags=["authentication"])
