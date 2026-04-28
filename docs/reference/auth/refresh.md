# Token Refresh

## V1 status

Status: `In V1`

## Purpose

Refresh access tokens without forcing unnecessary full login flows.

## Evidence to map

- Client source: `libs/common/src/services/api.service.ts`
- Server source: not mapped yet

## SDK implication

Refresh must be concurrency-safe so simultaneous SDK calls do not trigger duplicate refresh storms.
