# SQLite Storage (Scaffolding Only)

This directory contains SQLite storage scaffolding for the Accumulate Lite Client. 

**IMPORTANT**: This is scaffolding only and is **NOT** used by the runtime. The actual implementation uses in-memory caching and direct API calls.

## Purpose

This scaffolding is provided for:
1. Future implementation reference
2. Demonstrating the storage layer architecture
3. Potential offline caching capabilities in future versions

## Files

- `schema.sql` - SQLite database schema definition
- `sqlite_store.go` - Go implementation (disabled by default)

## Current Status

The SQLite storage layer is:
- ✅ Scaffolded with complete interface
- ❌ Not connected to the runtime
- ❌ Not used for actual data storage
- ⏳ Reserved for future implementation

## Why Scaffolding Only?

The current lite client implementation prioritizes:
1. Direct API access for real-time data
2. In-memory caching for performance
3. Minimal dependencies and complexity

SQLite storage may be enabled in future versions for:
- Offline mode support
- Long-term proof caching
- Historical data retention
- Performance optimization for frequently accessed data