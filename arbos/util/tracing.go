// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

package util

import (
	"encoding/binary"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
)

type TracingScenario uint64

const (
	TracingBeforeEVM TracingScenario = iota
	TracingDuringEVM
	TracingAfterEVM
)

type TracingInfo struct {
	Tracer   vm.EVMLogger
	Scenario TracingScenario
	Contract *vm.Contract
	Depth    int
}

// holds an address to satisfy core/vm's ContractRef() interface
type addressHolder struct {
	addr common.Address
}

func (a addressHolder) Address() common.Address {
	return a.addr
}

func NewTracingInfo(evm *vm.EVM, from, to common.Address, scenario TracingScenario) *TracingInfo {
	if evm.Config.Tracer == nil {
		return nil
	}
	return &TracingInfo{
		Tracer:   evm.Config.Tracer,
		Scenario: scenario,
		Contract: vm.NewContract(addressHolder{to}, addressHolder{from}, uint256.NewInt(0), 0),
		Depth:    evm.Depth(),
	}
}

func (info *TracingInfo) RecordStorageGet(key common.Hash) {
	tracer := info.Tracer
	if info.Scenario == TracingDuringEVM {
		scope := &vm.ScopeContext{
			Memory:   vm.NewMemory(),
			Stack:    TracingStackFromArgs(HashToUint256(key)),
			Contract: info.Contract,
		}
		tracer.CaptureState(0, vm.SLOAD, 0, 0, scope, []byte{}, info.Depth, nil)
	} else {
		tracer.CaptureArbitrumStorageGet(key, info.Depth, info.Scenario == TracingBeforeEVM)
	}
}

func (info *TracingInfo) RecordStorageSet(key, value common.Hash) {
	tracer := info.Tracer
	if info.Scenario == TracingDuringEVM {
		scope := &vm.ScopeContext{
			Memory:   vm.NewMemory(),
			Stack:    TracingStackFromArgs(HashToUint256(key), HashToUint256(value)),
			Contract: info.Contract,
		}
		tracer.CaptureState(0, vm.SSTORE, 0, 0, scope, []byte{}, info.Depth, nil)
	} else {
		tracer.CaptureArbitrumStorageSet(key, value, info.Depth, info.Scenario == TracingBeforeEVM)
	}
}

func (info *TracingInfo) MockCall(input []byte, gas uint64, from, to common.Address, amount *big.Int) {
	tracer := info.Tracer
	depth := info.Depth

	contract := vm.NewContract(addressHolder{to}, addressHolder{from}, uint256.MustFromBig(amount), gas)

	scope := &vm.ScopeContext{
		Memory: TracingMemoryFromBytes(input),
		Stack: TracingStackFromArgs(
			*uint256.NewInt(gas),                        // gas
			*uint256.NewInt(0).SetBytes(to.Bytes()),     // to address
			*uint256.NewInt(0).SetBytes(amount.Bytes()), // call value
			*uint256.NewInt(0),                          // memory offset
			*uint256.NewInt(uint64(len(input))),         // memory length
			*uint256.NewInt(0),                          // return offset
			*uint256.NewInt(0),                          // return size
		),
		Contract: contract,
	}
	tracer.CaptureState(0, vm.CALL, 0, 0, scope, []byte{}, depth, nil)
	tracer.CaptureEnter(vm.INVALID, from, to, input, 0, amount)

	retScope := &vm.ScopeContext{
		Memory: vm.NewMemory(),
		Stack: TracingStackFromArgs(
			*uint256.NewInt(0), // return offset
			*uint256.NewInt(0), // return size
		),
		Contract: contract,
	}
	tracer.CaptureState(0, vm.RETURN, 0, 0, retScope, []byte{}, depth+1, nil)
	tracer.CaptureExit(nil, 0, nil)

	popScope := &vm.ScopeContext{
		Memory: vm.NewMemory(),
		Stack: TracingStackFromArgs(
			*uint256.NewInt(1), // CALL result success
		),
		Contract: contract,
	}
	tracer.CaptureState(0, vm.POP, 0, 0, popScope, []byte{}, depth, nil)
}

func (info *TracingInfo) CaptureEVMTraceForHostio(name string, args, outs []byte, startInk, endInk uint64, scope *vm.ScopeContext, depth int) {
	intToBytes := func(v int) []byte {
		return binary.BigEndian.AppendUint64(nil, uint64(v))
	}

	checkArgs := func(want int) bool {
		if len(args) < want {
			log.Warn("tracing: missing arguments for hostio", "name", name, "want", want, "got", len(args))
			return false
		}
		return true
	}

	checkOuts := func(want int) bool {
		if len(args) < want {
			log.Warn("tracing: missing outputs for hostio", "name", name, "want", want, "got", len(args))
			return false
		}
		return true
	}

	firstOpcode := true
	capture := func(op vm.OpCode, stackValues ...[]byte) {
		const inkToGas = 10000
		var gas, cost uint64
		if firstOpcode {
			gas = startInk / inkToGas
			cost = (startInk - endInk) / inkToGas
			firstOpcode = false
		} else {
			// When capturing multiple opcodes, usually the first one is the relevant
			// action and the following ones just pop the result values from the stack.
			gas = endInk / inkToGas
			cost = 0
		}

		stack := []uint256.Int{}
		for _, value := range stackValues {
			stack = append(stack, *uint256.NewInt(0).SetBytes(value))
		}
		scope := &vm.ScopeContext{
			Memory:   scope.Memory,
			Stack:    TracingStackFromArgs(stack...),
			Contract: scope.Contract,
		}

		info.Tracer.CaptureState(0, op, gas, cost, scope, []byte{}, depth, nil)
	}

	switch name {
	case "read_args":
		capture(vm.CALLDATACOPY,
			nil,                   // destOffset
			nil,                   // offset
			intToBytes(len(outs)), // size
		)

	case "exit_early":
		if !checkArgs(4) {
			return
		}
		status := binary.BigEndian.Uint32(args[:4])
		var opcode vm.OpCode
		if status == 0 {
			opcode = vm.RETURN
		} else {
			opcode = vm.REVERT
		}
		capture(opcode,
			nil, // offset
			nil, // size
		)

	case "storage_load_bytes32":
		if !checkArgs(32) || !checkOuts(32) {
			return
		}
		capture(vm.SLOAD, args[:32]) // key
		capture(vm.POP, outs[:32])   // value

	case "storage_cache_bytes32":
		if !checkArgs(32 + 32) {
			return
		}
		capture(vm.SSTORE,
			args[:32],   // key
			args[32:64], // value
		)

	case "storage_flush_cache":
		// SSTORE is handled above by storage_cache_bytes32

	case "transient_load_bytes32":
		if !checkArgs(32) || !checkOuts(32) {
			return
		}
		capture(vm.TLOAD, args[:32]) // key
		capture(vm.POP, outs[:32])   // value

	case "transient_store_bytes32":
		if !checkArgs(32 + 32) {
			return
		}
		capture(vm.TSTORE,
			args[:32],   // key
			args[32:64], // value
		)

	case "call_contract":
		// Tracing: emit the call (value transfer is done later in evm.Call)
		//if tracingInfo != nil {
		//	var args []uint256.Int
		//	args = append(args, *uint256.NewInt(gas))                          // gas
		//	args = append(args, *uint256.NewInt(0).SetBytes(contract.Bytes())) // to address
		//	if opcode == vm.CALL {
		//		args = append(args, *uint256.NewInt(0).SetBytes(value.Bytes())) // call value
		//	}
		//	args = append(args, *uint256.NewInt(0))                  // memory offset
		//	args = append(args, *uint256.NewInt(uint64(len(input)))) // memory length
		//	args = append(args, *uint256.NewInt(0))                  // return offset
		//	args = append(args, *uint256.NewInt(0))                  // return size
		//	s := &vm.ScopeContext{
		//		Memory:   util.TracingMemoryFromBytes(input),
		//		Stack:    util.TracingStackFromArgs(args...),
		//		Contract: scope.Contract,
		//	}
		//	tracingInfo.Tracer.CaptureState(0, opcode, startGas, baseCost+gas, s, []byte{}, depth, nil)
		//}

		// TODO

	case "delegate_call_contract":
		// TODO

	case "static_call_contract":
		// TODO

	case "create1":
		if !checkArgs(32) || !checkOuts(20) {
			return
		}
		code := args[32:]
		capture(vm.CREATE,
			args[:32],             // value
			nil,                   // offset
			intToBytes(len(code)), // size
		)
		capture(vm.POP, outs[:20]) // address

	case "create2":
		if !checkArgs(32+32) || !checkOuts(20) {
			return
		}
		code := args[64:]
		capture(vm.CREATE2,
			args[:32],             // value
			nil,                   // offset
			intToBytes(len(code)), // size
			args[32:64],           // salt
		)
		capture(vm.POP, outs[:20]) // address

	case "read_return_data":
		if !checkArgs(8) {
			return
		}
		capture(vm.RETURNDATACOPY,
			nil,       // destOffset
			args[:4],  // offset
			args[4:8], // size
		)

	case "return_data_size":
		if !checkOuts(4) {
			return
		}
		capture(vm.RETURNDATASIZE)
		capture(vm.POP, outs[:4]) // size

	case "emit_log":
		if !checkArgs(4) {
			return
		}
		numTopics := int(binary.BigEndian.Uint32(args[:4]))
		dataOffset := 4 + 32*numTopics
		if !checkArgs(dataOffset) {
			return
		}
		data := args[dataOffset:]
		stack := [][]byte{
			nil,                   // offset
			intToBytes(len(data)), // size
		}
		for i := 0; i < numTopics; i++ {
			stack = append(stack, args[4+32*i:4+32*(i+1)])
		}
		opcode := vm.LOG0 + vm.OpCode(numTopics)
		capture(opcode, stack...)

	case "account_balance":
		if !checkArgs(20) || !checkOuts(32) {
			return
		}
		capture(vm.BALANCE, args[:20]) // address
		capture(vm.POP, outs[:32])     // balance

	case "account_code":
		if !checkArgs(20 + 4 + 4) {
			return
		}
		capture(vm.EXTCODECOPY,
			args[:20],   // address
			nil,         // destOffset
			args[20:24], // offset
			args[24:28], // size
		)

	case "account_code_size":
		if !checkArgs(20) || !checkOuts(4) {
			return
		}
		capture(vm.EXTCODESIZE, args[:20]) // address
		capture(vm.POP, outs[:4])          // size

	case "account_codehash":
		if !checkArgs(20) || !checkOuts(32) {
			return
		}
		capture(vm.EXTCODEHASH, args[:20]) // address
		capture(vm.POP, outs[:32])         // hash

	case "block_basefee":
		if !checkOuts(32) {
			return
		}
		capture(vm.BASEFEE)
		capture(vm.POP, outs[:32]) // baseFee

	case "block_coinbase":
		if !checkOuts(20) {
			return
		}
		capture(vm.COINBASE)
		capture(vm.POP, outs[:20]) // address

	case "block_gas_limit":
		if !checkOuts(8) {
			return
		}
		capture(vm.GASLIMIT)
		capture(vm.POP, outs[:8]) // gasLimit

	case "block_number":
		if !checkOuts(8) {
			return
		}
		capture(vm.NUMBER)
		capture(vm.POP, outs[:8]) // blockNumber

	case "block_timestamp":
		if !checkOuts(8) {
			return
		}
		capture(vm.TIMESTAMP)
		capture(vm.POP, outs[:8]) // timestamp

	case "chainid":
		if !checkOuts(8) {
			return
		}
		capture(vm.CHAINID)
		capture(vm.POP, outs[:8]) // chainId

	case "contract_address":
		if !checkOuts(20) {
			return
		}
		capture(vm.ADDRESS)
		capture(vm.POP, outs[:20]) // address

	case "evm_gas_left", "evm_ink_left":
		if !checkOuts(8) {
			return
		}
		capture(vm.GAS)
		capture(vm.POP, outs[:8]) // gas

	case "math_div":
		if !checkArgs(32+32) || !checkOuts(32) {
			return
		}
		capture(vm.DIV,
			args[:32],   // a
			args[32:64], // b
		)
		capture(vm.POP, outs[:32]) // result

	case "math_mod":
		if !checkArgs(32+32) || !checkOuts(32) {
			return
		}
		capture(vm.MOD,
			args[:32],   // a
			args[32:64], // b
		)
		capture(vm.POP, outs[:32]) // result

	case "math_pow":
		if !checkArgs(32+32) || !checkOuts(32) {
			return
		}
		capture(vm.EXP,
			args[:32],   // a
			args[32:64], // b
		)
		capture(vm.POP, outs[:32]) // result

	case "math_add_mod":
		if !checkArgs(32+32+32) || !checkOuts(32) {
			return
		}
		capture(vm.ADDMOD,
			args[:32],   // a
			args[32:64], // b
			args[64:96], // c
		)
		capture(vm.POP, outs[:32]) // result

	case "math_mul_mod":
		if !checkArgs(32+32+32) || !checkOuts(32) {
			return
		}
		capture(vm.MULMOD,
			args[:32],   // a
			args[32:64], // b
			args[64:96], // c
		)
		capture(vm.POP, outs[:32]) // result

	case "msg_sender":
		if !checkOuts(20) {
			return
		}
		capture(vm.CALLER)
		capture(vm.POP, outs[:20]) // address

	case "msg_value":
		if !checkOuts(32) {
			return
		}
		capture(vm.CALLVALUE)
		capture(vm.POP, outs[:32]) // value

	case "native_keccak256":
		if !checkOuts(32) {
			return
		}
		capture(vm.KECCAK256,
			nil,                   // offset
			intToBytes(len(args)), // size
		)
		capture(vm.POP, outs[:32]) // hash

	case "tx_gas_price":
		if !checkOuts(32) {
			return
		}
		capture(vm.GASPRICE)
		capture(vm.POP, outs[:32]) // price

	case "tx_ink_price":
		if !checkOuts(4) {
			return
		}
		capture(vm.GASPRICE)
		capture(vm.POP, outs[:4]) // price

	case "tx_origin":
		if !checkOuts(20) {
			return
		}
		capture(vm.ORIGIN)
		capture(vm.POP, outs[:20]) // address

	case "user_entrypoint", "user_returned", "msg_reentrant", "write_result", "pay_for_memory_grow", "console_log_test", "console_log":
		// No EVM counterpart

	default:
		log.Warn("unhandled hostio trace", "name", name)
	}
}

func HashToUint256(hash common.Hash) uint256.Int {
	value := uint256.Int{}
	value.SetBytes(hash.Bytes())
	return value
}

// TracingMemoryFromBytes creates an EVM Memory consisting of the bytes provided
func TracingMemoryFromBytes(input []byte) *vm.Memory {
	memory := vm.NewMemory()
	inputLen := uint64(len(input))
	memory.Resize(inputLen)
	memory.Set(0, inputLen, input)
	return memory
}

// TracingStackFromArgs creates an EVM Stack with the given arguments in canonical order
func TracingStackFromArgs(args ...uint256.Int) *vm.Stack {
	stack := &vm.Stack{}
	for flip := 0; flip < len(args)/2; flip++ { // reverse the order
		flop := len(args) - flip - 1
		args[flip], args[flop] = args[flop], args[flip]
	}
	stack.SetData(args)
	return stack
}
