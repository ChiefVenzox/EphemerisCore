# Ephemeris Core - Protocol Spec

This document describes the prototype logic for planetary distance based authentication with Ghost Seal and Time-Shift PIN.

## Core Flow
1. Register user (username, password).
2. Login with password + planet + PIN.
3. On first login, enroll device (Ghost Seal).
4. Subsequent logins require Ghost Seal.

## Hash Formula
SHA-512( Password + Distance_At_Shifted_Time + Ghost_Seal )

Shifted time:
T' = T - (PIN * 60 seconds)

## Notes
- Prototype only. Not for production.
- TLS is required in real deployments.

