package outbox

import sharedtypes "github.com/assurrussa/outbox/shared/types"

type (
	TypeSet   = sharedtypes.TypeSet
	JobID     = sharedtypes.JobID
	MessageID = sharedtypes.MessageID
)

var (
	ErrJobIDUuidZero     = sharedtypes.ErrJobIDUuidZero
	ErrMessageIDUuidZero = sharedtypes.ErrMessageIDUuidZero
	JobIDNil             = sharedtypes.JobIDNil
	MessageIDNil         = sharedtypes.MessageIDNil
)

func Parse[T TypeSet](s string) (T, error) {
	return sharedtypes.Parse[T](s)
}

func MustParse[T TypeSet](s string) T {
	return sharedtypes.MustParse[T](s)
}

func NewJobID() JobID {
	return sharedtypes.NewJobID()
}

func NewMessageID() MessageID {
	return sharedtypes.NewMessageID()
}
