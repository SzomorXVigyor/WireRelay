package main

import (
	"context"
	"crypto/subtle"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// extractToken retrieves the authentication token from gRPC incoming metadata.
// Accepts either "authorization: Bearer <token>" or "x-wirerelay-token: <token>".
func extractToken(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if vals := md.Get("authorization"); len(vals) > 0 {
		raw := strings.TrimSpace(vals[0])
		if len(raw) > 7 && strings.EqualFold(raw[:7], "Bearer ") {
			return strings.TrimSpace(raw[7:])
		}
	}
	if vals := md.Get("x-wirerelay-token"); len(vals) > 0 {
		return strings.TrimSpace(vals[0])
	}
	return ""
}

func validateToken(ctx context.Context, expected string) error {
	if expected == "" {
		return nil
	}
	provided := extractToken(ctx)
	if provided == "" {
		return status.Error(codes.Unauthenticated, "missing authentication token")
	}
	if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
		return status.Error(codes.Unauthenticated, "invalid authentication token")
	}
	return nil
}

func unaryAuthInterceptor(expectedToken string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := validateToken(ctx, expectedToken); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func streamAuthInterceptor(expectedToken string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := validateToken(ss.Context(), expectedToken); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}
