// Copyright 2022-2024, Offchain Labs, Inc.
// For license information, see https://github.com/OffchainLabs/nitro/blob/master/LICENSE

package arbtest

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/holiman/uint256"
	"github.com/offchainlabs/nitro/arbos/util"
	"github.com/offchainlabs/nitro/solgen/go/precompilesgen"
	"github.com/offchainlabs/nitro/util/testhelpers"
	"golang.org/x/crypto/sha3"
)

func traceCall(t *testing.T, b *NodeBuilder, program common.Address, data []byte) logger.ExecutionResult {
	type TraceCallMessage struct {
		From                 *common.Address   `json:"from"`
		To                   *common.Address   `json:"to"`
		Gas                  *hexutil.Uint64   `json:"gas"`
		GasPrice             *hexutil.Big      `json:"gasPrice"`
		MaxFeePerGas         *hexutil.Big      `json:"maxFeePerGas"`
		MaxPriorityFeePerGas *hexutil.Big      `json:"maxPriorityFeePerGas"`
		Value                *hexutil.Big      `json:"value"`
		Nonce                *hexutil.Uint64   `json:"nonce"`
		SkipL1Charging       *bool             `json:"skipL1Charging"`
		Data                 *hexutil.Bytes    `json:"data"`
		Input                *hexutil.Bytes    `json:"input"`
		AccessList           *types.AccessList `json:"accessList,omitempty"`
		ChainID              *hexutil.Big      `json:"chainId,omitempty"`
	}

	var result logger.ExecutionResult
	callMsg := TraceCallMessage{
		From: &b.L2Info.Accounts["Owner"].Address,
		To:   &program,
		Data: (*hexutil.Bytes)(&data),
	}
	rpcClient := b.L2.ConsensusNode.Stack.Attach()
	err := rpcClient.CallContext(b.ctx, &result, "debug_traceCall", callMsg, "latest", nil)
	Require(t, err, "failed to trace call")

	for i, log := range result.StructLogs {
		if log.Stack == nil {
			stack := []string{}
			log.Stack = &stack
		}
		t.Log("Trace call: i =", i, "| OpCode =", log.Op, "| Stack =", *log.Stack)
	}

	return result
}

func checkOpcode(t *testing.T, result logger.ExecutionResult, index int, wantOp vm.OpCode, wantStackSize int) {
	CheckEqual(t, wantOp.String(), result.StructLogs[index].Op)
	CheckEqual(t, wantStackSize, len(*result.StructLogs[index].Stack))
}

func checkOpcodeStack(t *testing.T, result logger.ExecutionResult, index int, wantOp vm.OpCode, wantStack ...[]byte) {
	checkOpcode(t, result, index, wantOp, len(wantStack))

	// reverse stack to canonical order
	for i, j := 0, len(wantStack)-1; i < j; i, j = i+1, j-1 {
		wantStack[i], wantStack[j] = wantStack[j], wantStack[i]

	}

	for i, wantBytes := range wantStack {
		wantVal := uint256.NewInt(0).SetBytes(wantBytes).Hex()
		CheckEqual(t, wantVal, (*result.StructLogs[index].Stack)[i])
	}
}

func intToBytes(v int) []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(v))
}

func TestTraceStylusStorage(t *testing.T) {
	const jit = false
	builder, auth, cleanup := setupProgramTest(t, jit)
	ctx := builder.ctx
	l2info := builder.L2Info
	l2client := builder.L2.Client
	defer cleanup()

	program := deployWasm(t, ctx, auth, l2client, rustFile("storage"))

	key := testhelpers.RandomHash()
	value := testhelpers.RandomHash()

	// Write value to key in transaction
	tx := l2info.PrepareTxTo("Owner", &program, l2info.TransferGas, nil, argsForStorageWrite(key, value))
	err := l2client.SendTransaction(ctx, tx)
	Require(t, err)
	_, err = EnsureTxSucceeded(ctx, l2client, tx)
	Require(t, err)

	// Trace write
	result := traceCall(t, builder, program, argsForStorageWrite(key, value))
	checkOpcodeStack(t, result, 3, vm.SSTORE, key[:], value[:])

	// Trace read
	result = traceCall(t, builder, program, argsForStorageRead(key))
	checkOpcodeStack(t, result, 3, vm.SLOAD, key[:])
	checkOpcodeStack(t, result, 4, vm.POP, value[:])
}

func TestTraceStylusEvmData(t *testing.T) {
	const jit = false
	builder, auth, cleanup := setupProgramTest(t, jit)
	ctx := builder.ctx
	l2info := builder.L2Info
	l2client := builder.L2.Client
	defer cleanup()

	program := deployWasm(t, ctx, auth, l2client, rustFile("evm-data"))

	programCode, err := l2client.CodeAt(ctx, program, nil)
	Require(t, err)

	programCodehasher := sha3.NewLegacyKeccak256()
	programCodehasher.Write(programCode)
	programCodehash := programCodehasher.Sum(nil)

	burnArbGas, _ := util.NewCallParser(precompilesgen.ArbosTestABI, "burnArbGas")
	gasToBurn := uint64(1000000)
	callBurnData, err := burnArbGas(new(big.Int).SetUint64(gasToBurn))
	Require(t, err)

	fundedAddr := l2info.GetAddress("Faucet")
	fundedBalance, err := l2client.BalanceAt(ctx, fundedAddr, nil)
	Require(t, err)

	ethPrecompile := common.BigToAddress(big.NewInt(1))
	arbTestAddress := types.ArbosTestAddress

	owner := l2info.GetAddress("Owner")

	data := []byte{}
	data = append(data, fundedAddr.Bytes()...)
	data = append(data, ethPrecompile.Bytes()...)
	data = append(data, arbTestAddress.Bytes()...)
	data = append(data, program.Bytes()...)
	data = append(data, callBurnData...)

	result := traceCall(t, builder, program, data)

	// read_args
	checkOpcodeStack(t, result, 2, vm.CALLDATACOPY, nil, nil, intToBytes(len(data)))

	// account_balance
	checkOpcodeStack(t, result, 3, vm.BALANCE, fundedAddr[:])
	checkOpcodeStack(t, result, 4, vm.POP, fundedBalance.Bytes())

	// account_codehash
	checkOpcodeStack(t, result, 9, vm.EXTCODEHASH, program[:])
	checkOpcodeStack(t, result, 10, vm.POP, programCodehash)

	// account_code_size
	checkOpcodeStack(t, result, 11, vm.EXTCODESIZE, program[:])
	checkOpcodeStack(t, result, 12, vm.POP, intToBytes(len(programCode)))

	// account_code
	checkOpcodeStack(t, result, 13, vm.EXTCODECOPY, program[:], nil, nil, intToBytes(len(programCode)))

	// block_basefee
	checkOpcodeStack(t, result, 26, vm.BASEFEE)
	checkOpcode(t, result, 27, vm.POP, 1)

	// chainid
	checkOpcodeStack(t, result, 28, vm.CHAINID)
	checkOpcodeStack(t, result, 29, vm.POP, intToBytes(412346))

	// block_coinbase
	checkOpcodeStack(t, result, 30, vm.COINBASE)
	checkOpcode(t, result, 31, vm.POP, 1)

	// block_gas_limit
	checkOpcodeStack(t, result, 32, vm.GASLIMIT)
	checkOpcode(t, result, 33, vm.POP, 1)

	// block_timestamp
	checkOpcodeStack(t, result, 34, vm.TIMESTAMP)
	checkOpcode(t, result, 35, vm.POP, 1)

	// contract_address
	checkOpcodeStack(t, result, 36, vm.ADDRESS)
	checkOpcodeStack(t, result, 37, vm.POP, program[:])

	// msg_sender
	checkOpcodeStack(t, result, 38, vm.CALLER)
	checkOpcodeStack(t, result, 39, vm.POP, owner[:])

	// msg_value
	checkOpcodeStack(t, result, 40, vm.CALLVALUE)
	checkOpcodeStack(t, result, 41, vm.POP, nil)

	// tx_origin
	checkOpcodeStack(t, result, 42, vm.ORIGIN)
	checkOpcodeStack(t, result, 43, vm.POP, owner[:])

	// tx_gas_price
	checkOpcodeStack(t, result, 44, vm.GASPRICE)
	checkOpcode(t, result, 45, vm.POP, 1)

	// tx_ink_price
	checkOpcodeStack(t, result, 46, vm.GASPRICE)
	checkOpcode(t, result, 47, vm.POP, 1)

	// block_number
	checkOpcodeStack(t, result, 48, vm.NUMBER)
	checkOpcode(t, result, 49, vm.POP, 1)

	// evm_gas_left
	checkOpcodeStack(t, result, 50, vm.GAS)
	checkOpcode(t, result, 51, vm.POP, 1)

	// evm_ink_left
	checkOpcodeStack(t, result, 52, vm.GAS)
	checkOpcode(t, result, 53, vm.POP, 1)
}

// TODO test:
//	case "exit_early":
//	case "transient_load_bytes32":
//	case "transient_store_bytes32":
//	case "call_contract":
//	case "delegate_call_contract":
//	case "static_call_contract":
//	case "create1":
//	case "create2":
//	case "read_return_data":
//	case "return_data_size":
//	case "emit_log":
//	case "math_div":
//	case "math_mod":
//	case "math_pow":
//	case "math_add_mod":
//	case "math_mul_mod":
//	case "msg_reentrant":
//	case "native_keccak256":
