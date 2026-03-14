package auth

import "context"

type actorCtxKey struct{}

// WithActor stores authenticated identity in request context.
func WithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, actorCtxKey{}, actor)
}

// ActorFromContext returns the authenticated actor if present.
func ActorFromContext(ctx context.Context) (Actor, bool) {
	v := ctx.Value(actorCtxKey{})
	if v == nil {
		return Actor{}, false
	}
	actor, ok := v.(Actor)
	return actor, ok
}
