package redis

import "github.com/go-redis/redis/v8"

// An Option configures a RedisClient
type Option interface {
	Apply(RedisClient)
}

// OptionFunc is a function that configures a RedisClient
type OptionFunc func(RedisClient)

// Apply is a function that set value to RedisClient
func (f OptionFunc) Apply(engine RedisClient) {
	f(engine)
}

func WithHooks(hooks ...redis.Hook) Option {
	return OptionFunc(func(rc RedisClient) {
		for _, hook := range hooks {
			rc.AddHook(hook)
		}
	})
}
