// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

package arbutil

// messages are 0-indexed
type MessageIndex uint64

// represents the number of messages
type MessageCount uint64

func BlockNumberToMessageCount(blockNumber uint64, genesisBlockNumber uint64) MessageCount {
	return MessageCount(blockNumber + 1 - genesisBlockNumber)
}

func MessageCountToBlockNumber(messageCount MessageCount, genesisBlockNumber uint64) int64 {
	return int64(uint64(messageCount)+genesisBlockNumber) - 1
}
