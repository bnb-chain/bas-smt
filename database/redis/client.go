package redis

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
)

var (
	_ RedisClient = (*redis.Client)(nil)
	_ RedisClient = (*redis.ClusterClient)(nil)
)

type RedisClient interface {
	FlushAll(ctx context.Context) *redis.StatusCmd
	Ping(ctx context.Context) *redis.StatusCmd
	Keys(ctx context.Context, pattern string) *redis.StringSliceCmd
	Exists(ctx context.Context, keys ...string) *redis.IntCmd
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
	EvalSha(ctx context.Context, sha1 string, keys []string, args ...interface{}) *redis.Cmd
	ScriptExists(ctx context.Context, scripts ...string) *redis.BoolSliceCmd
	ScriptLoad(ctx context.Context, script string) *redis.StringCmd
	Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
	ExpireAt(ctx context.Context, key string, tm time.Time) *redis.BoolCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Get(ctx context.Context, key string) *redis.StringCmd
	MGet(ctx context.Context, keys ...string) *redis.SliceCmd
	MSet(ctx context.Context, values ...interface{}) *redis.StatusCmd
	HDel(ctx context.Context, key string, fields ...string) *redis.IntCmd
	HExists(ctx context.Context, key, field string) *redis.BoolCmd
	HGet(ctx context.Context, key, field string) *redis.StringCmd
	HGetAll(ctx context.Context, key string) *redis.StringStringMapCmd
	HIncrBy(ctx context.Context, key, field string, incr int64) *redis.IntCmd
	HIncrByFloat(ctx context.Context, key, field string, incr float64) *redis.FloatCmd
	HKeys(ctx context.Context, key string) *redis.StringSliceCmd
	HLen(ctx context.Context, key string) *redis.IntCmd
	HMGet(ctx context.Context, key string, fields ...string) *redis.SliceCmd
	HSet(ctx context.Context, key string, values ...interface{}) *redis.IntCmd
	HSetNX(ctx context.Context, key, field string, value interface{}) *redis.BoolCmd
	HVals(ctx context.Context, key string) *redis.StringSliceCmd

	BLPop(ctx context.Context, timeout time.Duration, keys ...string) *redis.StringSliceCmd
	BRPop(ctx context.Context, timeout time.Duration, keys ...string) *redis.StringSliceCmd
	BRPopLPush(ctx context.Context, source, destination string, timeout time.Duration) *redis.StringCmd
	LIndex(ctx context.Context, key string, index int64) *redis.StringCmd
	LInsert(ctx context.Context, key, op string, pivot, value interface{}) *redis.IntCmd
	LInsertBefore(ctx context.Context, key string, pivot, value interface{}) *redis.IntCmd
	LInsertAfter(ctx context.Context, key string, pivot, value interface{}) *redis.IntCmd
	LLen(ctx context.Context, key string) *redis.IntCmd
	LPop(ctx context.Context, key string) *redis.StringCmd
	LPopCount(ctx context.Context, key string, count int) *redis.StringSliceCmd
	LPos(ctx context.Context, key string, value string, args redis.LPosArgs) *redis.IntCmd
	LPosCount(ctx context.Context, key string, value string, count int64, args redis.LPosArgs) *redis.IntSliceCmd
	LPush(ctx context.Context, key string, values ...interface{}) *redis.IntCmd
	LPushX(ctx context.Context, key string, values ...interface{}) *redis.IntCmd
	LRange(ctx context.Context, key string, start, stop int64) *redis.StringSliceCmd
	LRem(ctx context.Context, key string, count int64, value interface{}) *redis.IntCmd
	LSet(ctx context.Context, key string, index int64, value interface{}) *redis.StatusCmd
	LTrim(ctx context.Context, key string, start, stop int64) *redis.StatusCmd
	RPop(ctx context.Context, key string) *redis.StringCmd
	RPopCount(ctx context.Context, key string, count int) *redis.StringSliceCmd
	RPopLPush(ctx context.Context, source, destination string) *redis.StringCmd
	RPush(ctx context.Context, key string, values ...interface{}) *redis.IntCmd
	RPushX(ctx context.Context, key string, values ...interface{}) *redis.IntCmd
	LMove(ctx context.Context, source, destination, srcpos, destpos string) *redis.StringCmd

	TxPipelined(ctx context.Context, fn func(redis.Pipeliner) error) ([]redis.Cmder, error)
	TxPipeline() redis.Pipeliner
	Pipelined(ctx context.Context, fn func(redis.Pipeliner) error) ([]redis.Cmder, error)
	Pipeline() redis.Pipeliner

	AddHook(hook redis.Hook)
	Close() error
}
